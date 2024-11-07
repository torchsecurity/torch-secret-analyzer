package time

import (
	"time"
)

func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
