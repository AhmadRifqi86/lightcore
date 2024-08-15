package util

import (
	"strings"
)

func EscapeDnn(dnn string) string {
	return strings.ReplaceAll(dnn, ".", "_")
}
