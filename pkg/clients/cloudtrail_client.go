package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/samber/lo"
	jsonutil "github.com/torchsecurity/torch-secret-analyzer/pkg/utils/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type CloudTrailEventResource struct {
	ResourceType string `json:"resourceType"`
	ResourceName string `json:"resourceName"`
}

type AWSUserIdentitySessionContextAttributes struct {
	MfaAuthenticated string     `json:"mfaAuthenticated"`
	CreationDate     *time.Time `json:"creationDate"`
}

type AWSUserIdentitySessionContextSessionIssuer struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountId   string `json:"accountId"`
	UserName    string `json:"userName"`
}

type AWSUserIdentitySessionContextWebIdFederationDataFederationAttributes struct {
	AppId  string `json:"appId"`
	UserId string `json:"userId"`
}

type AWSUserIdentitySessionContextWebIdFederationData struct {
	FederatedProvider string                                                                `json:"federatedProvider"`
	Attributes        *AWSUserIdentitySessionContextWebIdFederationDataFederationAttributes `json:"attributes"`
}

type AWSUserIdentitySessionContext struct {
	Attributes          *AWSUserIdentitySessionContextAttributes          `json:"attributes"`
	SessionIssuer       *AWSUserIdentitySessionContextSessionIssuer       `json:"sessionIssuer"`
	Ec2RoleDelivery     string                                            `json:"ec2RoleDelivery"`
	WebIdFederationData *AWSUserIdentitySessionContextWebIdFederationData `json:"webIdFederationData"`
}

type AWSUserIdentity struct {
	Type             string                         `json:"type"`
	PrincipalId      string                         `json:"principalId"`
	Arn              string                         `json:"arn"`
	AccountId        string                         `json:"accountId"`
	UserName         string                         `json:"userName"`
	AccessKeyId      string                         `json:"accessKeyId"`
	InvokedBy        string                         `json:"invokedBy"`
	SessionContext   *AWSUserIdentitySessionContext `json:"sessionContext"`
	IdentityProvider string                         `json:"identityProvider"`
}

type cloudtrailRawEvent struct {
	UserIdentity      AWSUserIdentity           `json:"userIdentity"`
	Resources         []CloudTrailEventResource `json:"resources"`
	RequestParameters map[string]interface{}    `json:"requestParameters"`
	ResponseElements  map[string]interface{}    `json:"responseElements"`
	EventCategory     string                    `json:"eventCategory"`
	SourceIpAddress   string                    `json:"sourceIpAddress"`
	UserAgent         string                    `json:"userAgent"`
}

type CloudtrailEvent struct {
	ExternalId        string
	EventName         string
	EventSource       string
	EventTime         time.Time
	Username          string
	Resources         []CloudTrailEventResource
	UserIdentity      AWSUserIdentity
	SourceIpAddress   string
	UserAgent         string
	RequestParameters string
	ResponseElements  string
	EventCategory     string
}

type CloudtrailClient struct {
	client *cloudtrail.Client
	region string
}

func NewCloudtrailClient(region string, profile string) (client *CloudtrailClient, err error) {
	// We pass region to the load default config. If region is empty, it uses the profile default region.
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region), config.WithSharedConfigProfile(profile))
	if err != nil {
		return nil, fmt.Errorf("could not load aws config %w", err)
	}

	cloudtrailClient := CloudtrailClient{
		client: cloudtrail.NewFromConfig(cfg),
		region: region,
	}
	return &cloudtrailClient, nil
}

type EventsFilter struct {
	EventName *string
}

func (c *CloudtrailClient) GetEvents(startTime time.Time, eventsFilter *EventsFilter) ([]CloudtrailEvent, error) {
	var lookupAttributes []types.LookupAttribute

	if eventsFilter.EventName != nil {
		lookupAttributes = append(lookupAttributes, types.LookupAttribute{
			AttributeKey:   "EventName",
			AttributeValue: eventsFilter.EventName,
		})
	}

	return c.queryEvents(startTime, lookupAttributes)
}

func (c *CloudtrailClient) queryEvents(startTime time.Time, lookupAttributes []types.LookupAttribute) ([]CloudtrailEvent, error) {
	cloudtrailRawEvents, err := c.queryCloudtrailEvents(startTime, lookupAttributes)
	if err != nil {
		return nil, fmt.Errorf("could not query cloudtrail events: %v", err)
	}

	var cloudtrailEvents []CloudtrailEvent
	for _, rawEvent := range cloudtrailRawEvents {
		cloudtrailEvent, err := parseCloudtrailEvent(rawEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to process event: %v", err)
		}
		cloudtrailEvents = append(cloudtrailEvents, *cloudtrailEvent)
	}

	return cloudtrailEvents, nil
}

func (c *CloudtrailClient) queryCloudtrailEvents(startTime time.Time, lookupAttributes []types.LookupAttribute) ([]types.Event, error) {
	cloudtrailEvents := []types.Event{}

	var nextToken *string
	for {
		resp, err := c.client.LookupEvents(context.Background(), &cloudtrail.LookupEventsInput{
			LookupAttributes: lookupAttributes,
			StartTime:        aws.Time(startTime),
			NextToken:        nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to lookup events: %v", err)
		}

		cloudtrailEvents = append(cloudtrailEvents, resp.Events...)

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return cloudtrailEvents, nil
}

func parseCloudtrailEvent(event types.Event) (cloudtrailEvent *CloudtrailEvent, err error) {
	extracedEvent, err := extractRawEvent(event)
	if err != nil {
		return nil, fmt.Errorf("could not parse cloudtrail event: %v", err)
	}

	// AWS is inconsistent in the way that the resources might appear in the raw event but not in the parsed event
	// and vise versa (For some reason...). TODO: Clean this up.
	resources := make([]CloudTrailEventResource, 0)
	if len(event.Resources) > 0 && extracedEvent.Resources == nil {
		for _, resource := range event.Resources {
			resources = append(resources, CloudTrailEventResource{
				ResourceType: lo.FromPtr(resource.ResourceType),
				ResourceName: lo.FromPtr(resource.ResourceName),
			})
		}
	} else if extracedEvent.Resources != nil {
		resources = extracedEvent.Resources
	}

	return &CloudtrailEvent{
		ExternalId:        *event.EventId,
		EventName:         *event.EventName,
		EventSource:       *event.EventSource,
		EventCategory:     extracedEvent.EventCategory,
		EventTime:         *event.EventTime,
		Username:          lo.FromPtr(event.Username),
		Resources:         resources,
		UserIdentity:      extracedEvent.UserIdentity,
		SourceIpAddress:   extracedEvent.SourceIpAddress,
		UserAgent:         extracedEvent.UserAgent,
		RequestParameters: jsonutil.MustMarshalToString(extracedEvent.RequestParameters),
		ResponseElements:  jsonutil.MustMarshalToString(extracedEvent.ResponseElements),
	}, nil
}

func extractRawEvent(event types.Event) (*cloudtrailRawEvent, error) {
	var rawEvent *cloudtrailRawEvent

	err := json.Unmarshal([]byte(*event.CloudTrailEvent), &rawEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize raw event: %v", err)
	}

	return rawEvent, nil
}
