package colors

import (
	"github.com/fatih/color"
)

var (
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgHiGreen).SprintFunc()
	Blue   = color.New(color.FgHiBlue).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
)
