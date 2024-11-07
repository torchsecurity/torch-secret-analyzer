package aws

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/collectors/aws_cloudtrail"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/engines"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/colors"
	timeutil "github.com/torchsecurity/torch-secret-analyzer/pkg/utils/time"
)

var consumersCommand = &cobra.Command{
	Use:   "consumers",
	Short: "Analyze AWS consumers",
	Long:  "Analyze the access to secrets stored in AWS Secrets Manager",
}

// shared flags between consumers commands
var (
	secretId     string
	region       string
	profileToUse string
)

var listActualCommand = &cobra.Command{
	Use:   "list-actual",
	Short: "List AWS secret's actual consumers",
	Long:  `Torch analyzes AWS Cloudtrail events and crosses information with AWS Secrets Manager to identify who are the "consumers" of a given secrets in a given timeframe`,
	Run: func(cmd *cobra.Command, args []string) {
		if secretId == "" {
			fmt.Println(cmd.UsageString())
			return
		}
		fmt.Printf("Listing all actual consumers of the secret '%s' based on AWS CloudTrail Events, filtering for read events in the last %d days:\n", secretId, daysBack)
		cloudtrailEvents, err := aws_cloudtrail.CollectCloudTrail(region, daysBack, profileToUse)
		if err != nil {
			fmt.Printf(colors.Red("Could not list AWS actual consumers: %w"), err)
			return
		}

		actualConsumers := engines.GetAWSActualConsumers(cloudtrailEvents, secretId)
		var humanConsumers []engines.Consumer
		var machineConsumers []engines.Consumer
		for _, consumer := range actualConsumers {
			if consumer.Category == engines.HumanConsumer {
				humanConsumers = append(humanConsumers, consumer)
			} else {
				machineConsumers = append(machineConsumers, consumer)
			}
		}

		if len(humanConsumers) > 0 {
			fmt.Print("\nHuman:\n")
			for _, consumer := range humanConsumers {
				fmt.Printf("* %s (last read on %s) (%s)\n", consumer.Name, timeutil.FormatTime(consumer.AccessedResourceAt), consumer.Type)
			}
		}

		if len(machineConsumers) > 0 {
			fmt.Print("\nMachine:\n")
			for _, consumer := range machineConsumers {
				fmt.Printf("* %s (last read on %s) (%s)\n", consumer.Name, timeutil.FormatTime(consumer.AccessedResourceAt), consumer.Type)
			}
		}
	},
}

// list-actual flags
var (
	daysBack int
)

var listPotentialCommand = &cobra.Command{
	Use:   "list-potential",
	Short: "List AWS secret's potential consumers",
	Long:  "Torch analyzes and correlates data across AWS IAM and AWS Secrets Manager to identify users and services with permission to access a certain secret",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(colors.Yellow("Coming soon!"))
	},
}

func init() {
	consumersCommand.PersistentFlags().StringVarP(&secretId, "secret-id", "s", "", "AWS secret ID (required).")
	consumersCommand.MarkFlagRequired("secret-id")
	consumersCommand.PersistentFlags().StringVarP(&region, "region", "r", "", "AWS region of the secret (will use aws profile by default).")
	consumersCommand.PersistentFlags().StringVarP(&profileToUse, "profile", "p", "", "The AWS profile the CLI tool should use (will use the active aws profile by default).")

	listActualCommand.Flags().IntVarP(&daysBack, "days-back", "d", 14, "The amount of days back to query AWS cloudtrail for its events (14 by default).")

	consumersCommand.AddCommand(listActualCommand)
	consumersCommand.AddCommand(listPotentialCommand)
}
