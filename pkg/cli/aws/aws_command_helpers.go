package aws

import (
	"os/exec"
	"strings"

	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/formatters"
)

type CommandOption func(args *[]string)

func withProfile(profile string) CommandOption {
	profile = strings.TrimSpace(profile)
	return func(commandArgs *[]string) {
		if profile != "" {
			*commandArgs = append(*commandArgs, "--profile", profile)
		}
	}
}

func createCommand(command string, options ...CommandOption) (finalCommand *exec.Cmd) {
	if command == "" {
		formatters.PrintErrorAndExit("No command was provided")
	}

	commandParts := strings.Fields(command)
	rootCommand := commandParts[0]
	commandArgs := commandParts[1:]
	for _, option := range options {
		option(&commandArgs)
	}
	return exec.Command(rootCommand, commandArgs...)
}
