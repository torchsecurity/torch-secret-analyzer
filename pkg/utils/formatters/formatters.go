package formatters

import (
	"fmt"
	"log"

	"github.com/torchsecurity/torch-secret-analyzer/pkg/utils/colors"
)

func PrintErrorAndExit(message string, params ...interface{}) {
	errorMessage := fmt.Sprintf(message, params...)
	log.Fatalln(colors.Red(errorMessage))
}
