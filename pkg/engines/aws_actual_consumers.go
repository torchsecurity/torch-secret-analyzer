package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/torchsecurity/torch-secret-analyzer/pkg/clients"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/collectors/aws_cloudtrail"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/colors"
)

type ConsumerCategory string

const (
	HumanConsumer   ConsumerCategory = "Human"
	MachineConsumer ConsumerCategory = "Machine"
)

type Consumer struct {
	Category             ConsumerCategory
	Type                 string
	Name                 string
	ExternalId           string
	ExternalResourceName string
	AccessKeyId          string
	AccessedResourceAt   time.Time
}

func GetAWSActualConsumers(cloudtrailEvents aws_cloudtrail.EventsByName, secretId string) []Consumer {
	getSecretValueEvents := filterEventsBySecret(cloudtrailEvents[aws_cloudtrail.GetSecretValueEvent], secretId)
	return getConsumers(getSecretValueEvents)
}

func filterEventsBySecret(cloudtrailEvents []clients.CloudtrailEvent, secretId string) []clients.CloudtrailEvent {
	var filterEvents []clients.CloudtrailEvent

	for _, event := range cloudtrailEvents {
		for _, resource := range event.Resources {
			if isResourceMatchingSecret(resource.ResourceName, secretId) {
				filterEvents = append(filterEvents, event)
				break
			}
		}
	}

	return filterEvents
}

// A Cloudtrail event resource's name could return as the secret name or the secret arn - depends on how the secrets manager's action was called.
// Therefore in order to filter the event by the secretId provided, we need to check if the the secretId is matching the resource name / resource arn.
func isResourceMatchingSecret(resourceName, secretId string) bool {
	// Check if the resource name is an exact match with the secret ID.
	if resourceName == secretId {
		return true
	}

	// If resource name is an ARN, extract the secret name part and compare.
	const arnPrefix = "arn:aws:secretsmanager:"
	const secretPrefix = "secret:"
	if strings.HasPrefix(resourceName, arnPrefix) {
		// Find the index of "secret:" in the ARN
		secretIndex := strings.Index(resourceName, secretPrefix)
		if secretIndex != -1 {
			// Extract the secret name portion
			start := secretIndex + len(secretPrefix)
			identifierName := resourceName[start:]

			// Use regex to match secret ID followed by a version ID (a hyphen and alphanumeric version pattern)
			pattern := fmt.Sprintf(`^%s-[a-zA-Z0-9]+$`, regexp.QuoteMeta(secretId))
			matched, _ := regexp.MatchString(pattern, identifierName)
			return matched
		}
	}

	return false
}

func getConsumers(events []clients.CloudtrailEvent) []Consumer {
	consumersLastEvents := map[string]Consumer{}
	for _, event := range events {
		consumer, err := extractConsumerFromEvent(event)
		if err != nil {
			fmt.Printf(colors.Yellow("Could not extract Consumer from event: %s\n"), event.EventCategory)
			continue
		}
		consumerLastEvent, exists := consumersLastEvents[consumer.ExternalId]
		if !exists || (exists && consumer.AccessedResourceAt.After(consumerLastEvent.AccessedResourceAt)) {
			consumersLastEvents[consumer.ExternalId] = consumer
		}
	}

	var consumers []Consumer
	for _, consumer := range consumersLastEvents {
		consumers = append(consumers, consumer)
	}
	return consumers
}

func extractConsumerFromEvent(event clients.CloudtrailEvent) (Consumer, error) {
	var err error
	consumer := Consumer{AccessedResourceAt: event.EventTime}

	userIdentity := event.UserIdentity

	if userIdentity.AccessKeyId != "" {
		consumer.AccessKeyId = userIdentity.AccessKeyId
	}

	if userIdentity.Type == "AssumedRole" || userIdentity.Type == "IAMRole" {
		err = identifyAssumedRoleAccessPrivileges(userIdentity, &consumer)
	} else {
		// Using an identity directly - treat principalId as the identity
		category, identityType := classifyAssumingConsumer(userIdentity)
		consumer.Category = category
		consumer.Type = identityType
		consumer.ExternalId = userIdentity.PrincipalId
		consumer.Name = userIdentity.UserName
		consumer.ExternalResourceName = userIdentity.Arn
	}

	return consumer, err
}

func identifyAssumedRoleAccessPrivileges(userIdentity clients.AWSUserIdentity, consumer *Consumer) error {
	if userIdentity.SessionContext == nil {
		return fmt.Errorf("missing session context for assumed role")
	}

	assumingPrincipalId := extractAssumingPrincipalId(userIdentity.PrincipalId)
	category, identityType := classifyAssumingConsumer(userIdentity)
	consumer.Category = category
	consumer.Type = identityType
	consumer.ExternalId = assumingPrincipalId
	consumer.Name = assumingPrincipalId
	consumer.ExternalResourceName = userIdentity.Arn

	return nil
}

func classifyAssumingConsumer(userIdentity clients.AWSUserIdentity) (category ConsumerCategory, identityType string) {
	roleArn := ""
	federatedProvider := ""

	if userIdentity.SessionContext != nil {
		if userIdentity.SessionContext.SessionIssuer != nil {
			roleArn = userIdentity.SessionContext.SessionIssuer.Arn
		}
		if userIdentity.SessionContext.WebIdFederationData != nil {
			federatedProvider = userIdentity.SessionContext.WebIdFederationData.FederatedProvider
		}
	}

	entityId := extractAssumingPrincipalId(userIdentity.PrincipalId)

	if federatedProvider != "" {
		if strings.Contains(federatedProvider, "oidc.eks.") {
			return MachineConsumer, "AWS EKS Service Account"
		}
	}
	if strings.HasPrefix(entityId, "i-") {
		return MachineConsumer, "AWS EC2 Instance"
	}
	if userIdentity.Type == "AWSService" || strings.Contains(roleArn, "/aws-service-role") {
		return MachineConsumer, "AWS Service"
	}
	if userIdentity.Type == "WebIdentityUser" || (strings.Contains(userIdentity.Arn, "sts.amazonaws.com:assumed-role") && strings.Contains(userIdentity.Arn, "WebIdentity")) {
		return HumanConsumer, "Web Identity User"
	}
	if userIdentity.Type == "SAMLUser" || strings.Contains(userIdentity.Arn, "AWSReservedSSO") {
		return HumanConsumer, "AWS SAML User"
	}
	if userIdentity.Type == "IAMUser" || strings.Contains(userIdentity.Arn, ":user/") {
		return HumanConsumer, "AWS IAM User"
	}
	if userIdentity.Type == "IAMRole" || strings.Contains(userIdentity.Arn, ":role/") {
		return MachineConsumer, "AWS IAM Role"
	}
	if userIdentity.Type == "FederatedUser" {
		return HumanConsumer, "AWS Federated User"
	}
	return MachineConsumer, "Application"
}

func extractAssumingPrincipalId(principalId string) string {
	parts := strings.Split(principalId, ":")
	if len(parts) < 2 {
		return principalId
	}
	return parts[1]
}
