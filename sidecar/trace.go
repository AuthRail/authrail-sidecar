package sidecar

import (
	"net/http"
	"regexp"
	"strings"
)

var traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// Trace context is correlation only. It is never part of an executor proof.
func validTraceparent(value string) bool {
	return value == "" || traceparentPattern.MatchString(value) &&
		value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
}

func requestTraceparent(r *http.Request) (string, bool) {
	values := r.Header.Values("traceparent")
	if len(values) > 1 {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], validTraceparent(values[0]) && values[0] != ""
}
