package aws_cloudtrail

import (
	"fmt"
	"time"

	"github.com/torchsecurity/torch-secret-analyzer/pkg/clients"
)

const (
	CreateSecretEvent   = "CreateSecret"
	GetSecretValueEvent = "GetSecretValue"
	PutSecretValueEvent = "PutSecretValue"
	UpdateSecretEvent   = "UpdateSecret"
	RotateSecretEvent   = "RotateSecret"
)

var SupportedEvents = []string{
	GetSecretValueEvent,
}

type EventsByName map[string][]clients.CloudtrailEvent

func CollectCloudTrail(region string, daysBack int, profile string) (cloudtrailEvents EventsByName, err error) {
	cloudtrailClient, err := clients.NewCloudtrailClient(region, profile)
	if err != nil {
		return nil, fmt.Errorf("could not initial cloudtrail client %w", err)
	}
	collector := NewCloudTrailCollector(region, profile, cloudtrailClient)
	return collector.Collect(daysBack)
}

type CloudTrailCollector struct {
	region           string
	profile          string
	cloudtrailClient *clients.CloudtrailClient
}

func NewCloudTrailCollector(region string, profile string, cloudtrailClient *clients.CloudtrailClient) *CloudTrailCollector {
	return &CloudTrailCollector{
		region:           region,
		profile:          profile,
		cloudtrailClient: cloudtrailClient,
	}
}

func (c *CloudTrailCollector) Collect(daysBack int) (cloudtrailEvents EventsByName, err error) {
	startTime := time.Now().AddDate(0, 0, -daysBack)
	allEvents := EventsByName{}
	for _, eventName := range SupportedEvents {
		events, err := c.cloudtrailClient.GetEvents(startTime, &clients.EventsFilter{EventName: &eventName})
		if err != nil {
			return nil, fmt.Errorf("error collecting cloudtrail data for event %s: %v", eventName, err)
		}
		allEvents[eventName] = append(allEvents[eventName], events...)
	}
	return allEvents, nil
}
