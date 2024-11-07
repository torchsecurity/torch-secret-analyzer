package aws

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/colors"
	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/formatters"
)

type ProfileType string

const (
	CredentialsProfile ProfileType = "credentials"
	SSOProfile         ProfileType = "sso"
	EnvProfile         ProfileType = "env"
	UnknownProfile     ProfileType = "unknown"
)

type AWSProfile struct {
	Name string
	Type ProfileType
}

var (
	profileToConfig string
)

var authCommand = &cobra.Command{
	Use:   "auth",
	Short: "AWS authentication",
	Long:  "Print and configure AWS authentication methods",
}

var configCommand = &cobra.Command{
	Use:   "config",
	Short: "Configure AWS authentication",
	Long:  "Configure a local AWS credentials profile",
	Run: func(cmd *cobra.Command, args []string) {
		configureAWSCredentials(profileToConfig)
	},
}

var configSSOCommand = &cobra.Command{
	Use:   "sso",
	Short: "Configure AWS SSO authentication",
	Long:  "Configure a local AWS SSO profile",
	Run: func(cmd *cobra.Command, args []string) {
		configureAWSSSO(profileToConfig)
	},
}

var configPrintCommand = &cobra.Command{
	Use:   "print",
	Short: "Print AWS authentication methods",
	Long:  "Print all AWS profiles",
	Run: func(cmd *cobra.Command, args []string) {
		configuredProfiles := getAWSProfiles()
		if len(configuredProfiles) == 0 {
			fmt.Println(colors.Yellow("No AWS profile is configured"))
		} else {
			fmt.Println("AWS configured profiles:")
			for _, profile := range configuredProfiles {
				fmt.Printf("* '%s' (%s)\n", profile.Name, profile.Type)
			}
		}
	},
}

func init() {
	authCommand.AddCommand(configCommand)
	authCommand.AddCommand(configPrintCommand)

	configCommand.PersistentFlags().StringVarP(&profileToConfig, "profile", "p", "", "The AWS profile to config (will use the active aws profile by default).")
	configCommand.AddCommand(configSSOCommand)
}

func configureAWS(typeToConfigure ProfileType, awsConfigCommand *exec.Cmd) {
	configuredProfiles := getAWSProfiles()

	profilesFromSameType := []AWSProfile{}
	for _, configuredProfile := range configuredProfiles {
		if configuredProfile.Type == typeToConfigure {
			profilesFromSameType = append(profilesFromSameType, configuredProfile)
		}
	}

	// If a profile is already configured, we ask the user if they want to configure a new one.
	if len(profilesFromSameType) > 0 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("AWS %s profile is already configured. Would you like to configure a new profile? (y/n): ", typeToConfigure)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" {
			fmt.Println("Keeping the current AWS profile configuration.")
			return
		}
	}

	awsConfigCommand.Stdin = os.Stdin
	awsConfigCommand.Stdout = os.Stdout
	awsConfigCommand.Stderr = os.Stderr

	if err := awsConfigCommand.Run(); err != nil {
		formatters.PrintErrorAndExit("Error while configuring aws: %v", err)
	}
}

// We support configuring a specific profile
func configureAWSCredentials(profile string) {
	configCommand := createCommand("aws configure", withProfile(profile))
	configureAWS(CredentialsProfile, configCommand)
}

// We support configuring a specific SSO profile
func configureAWSSSO(profile string) {
	configSSOCommand := createCommand("aws configure sso", withProfile(profile))
	configureAWS(SSOProfile, configSSOCommand)
	loginSSO(profile)
}

// Runs `aws sso login` to log into the configured SSO profile
func loginSSO(profile string) {
	loginCommand := createCommand("aws sso login", withProfile(profile))
	loginCommand.Stdin = os.Stdin
	loginCommand.Stdout = os.Stdout
	loginCommand.Stderr = os.Stderr

	if err := loginCommand.Run(); err != nil {
		formatters.PrintErrorAndExit("Error running aws sso login: %v", err)
	} else {
		fmt.Println("Logged in to AWS SSO successfully.")
	}
}

func getAWSProfiles() []AWSProfile {
	profiles := []AWSProfile{}

	listProfilesCommand := createCommand("aws configure list-profiles")
	var profilesOut bytes.Buffer
	listProfilesCommand.Stdout = &profilesOut
	if err := listProfilesCommand.Run(); err != nil {
		formatters.PrintErrorAndExit("Error listing profiles: %v", err)
	}

	profileNames := strings.Split(profilesOut.String(), "\n")
	for _, profileName := range profileNames {
		// We pass --profile to aws configure list command, to check if the profile is active.
		listSpecificProfileCommand := createCommand("aws configure list", withProfile(profileName))
		var profileOut bytes.Buffer
		listSpecificProfileCommand.Stdout = &profileOut
		if err := listSpecificProfileCommand.Run(); err != nil {
			formatters.PrintErrorAndExit("Error reading profile '%s': %v", profileName, err)
		}
		profile := parseAWSProfileOutput(profileOut.String(), profileName)
		profiles = append(profiles, profile)
	}
	return profiles
}

/*
'aws configure list --profile <profile_name>' output structure:

	   Name                    Value             Type    Location
	   ----                    -----             ----    --------
	profile           <profile_name>           manual    --profile

access_key     ****************XXXX   <profile_type>
secret_key     ****************ZZZZ   <profile_type>

	region                 <region>      config-file    ~/.aws/config
*/
func parseAWSProfileOutput(profileOutput string, profileName string) AWSProfile {
	profile := AWSProfile{Name: profileName}
	profileOutputLines := strings.Split(profileOutput, "\n")
	for _, line := range profileOutputLines {
		// Each aws profile contains an access_key row which indicates the type of the profile
		if strings.Contains(line, "access_key") {
			re := regexp.MustCompile(`\s+`)
			accessKeyLineParts := re.Split(line, -1)
			profileTypePart := accessKeyLineParts[2]
			profile.Type = parseProfileType(profileTypePart)
			break
		}
	}
	return profile
}

func parseProfileType(profileTypeOutput string) ProfileType {
	outputToProfileType := map[string]ProfileType{
		"sso":                     SSOProfile,
		"env":                     EnvProfile,
		"shared-credentials-file": CredentialsProfile,
	}

	if profileType, exists := outputToProfileType[profileTypeOutput]; exists {
		return profileType
	}
	return UnknownProfile
}
