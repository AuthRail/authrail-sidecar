package sidecar

import (
	"net/http/httptest"
	"testing"
)

func TestTraceparentBoundary(t *testing.T) {
	for _, example := range []struct {
		value    string
		accepted bool
	}{
		{"", true},
		{"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", true},
		{"00-00000000000000000000000000000000-0123456789abcdef-01", false},
		{"00-0123456789abcdef0123456789abcdef-0000000000000000-01", false},
		{"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01,evil", false},
	} {
		request := httptest.NewRequest("POST", "/evaluate", nil)
		if example.value != "" {
			request.Header.Set("traceparent", example.value)
		}
		_, accepted := requestTraceparent(request)
		if accepted != example.accepted {
			t.Errorf("trace %q accepted=%v", example.value, accepted)
		}
	}
}
