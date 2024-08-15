package util

import (
	"encoding/json"
	"strings"

	"github.com/free5gc/smf/internal/logger"
)

func EscapeDnn(dnn string) string {
	return strings.ReplaceAll(dnn, ".", "_")
}

func UnescapeDnn(dnnKey string) string {
	return strings.ReplaceAll(dnnKey, "_", ".")
}

func MapToByte(data map[string]interface{}) []byte {
	ret, err := json.Marshal(data)
	if err != nil {
		logger.UtilLog.Error(err)
	}
	return ret
}
