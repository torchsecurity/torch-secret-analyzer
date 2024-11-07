package aws

import (
	"github.com/spf13/cobra"
)

var AWSCommand = &cobra.Command{
	Use:   "aws",
	Short: "Analyze AWS secrets manager",
	Long:  "Analyze the access to secrets stored in AWS Secrets Manager",
}

func init() {
	AWSCommand.AddCommand(authCommand)
	AWSCommand.AddCommand(consumersCommand)
}
