package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Diagnostic output must not disclose caller-controlled text with or without OTLP.
func TestRuntimeLogsAreRedactedWithAndWithoutOTLP(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	for _, endpoint := range []string{"", collector.URL} {
		t.Run(map[bool]string{true: "disabled", false: "enabled"}[endpoint == ""], func(t *testing.T) {
			var output bytes.Buffer
			logs := NewRuntimeLogs(&output)
			telemetry, err := NewTelemetry(context.Background(), endpoint)
			if err != nil {
				t.Fatal(err)
			}
			telemetry.WithRuntimeLogs(logs)
			secret := "private-body-and-credential"
			handler := telemetry.WrapHTTP("evaluate", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				telemetry.RecordDecision(r.Context(), Evaluation{RequestID: "d89895fe-f2f4-41ab-bfae-55892bbe995b",
					ActionID: secret, Mode: "enforce", Outcome: "deny", RecordingStatus: "retained", ReasonCodes: []string{secret}}, "tool_call")
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodPost, "/evaluate?secret="+secret, strings.NewReader(secret))
			request.Header.Set("Authorization", "Bearer "+secret)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			logs.Shutdown(context.Background())
			_ = telemetry.Shutdown(context.Background())
			if response.Code != http.StatusOK || strings.Contains(output.String(), secret) {
				t.Fatal("diagnostics changed the response or disclosed caller content")
			}
			for _, expected := range []string{`"event":"decision"`, `"outcome":"deny"`, `"recordingStatus":"retained"`, `"event":"request_completed"`} {
				if !strings.Contains(output.String(), expected) {
					t.Fatalf("missing log field %s", expected)
				}
			}
		})
	}
}

type stalledLogWriter struct{ release chan struct{} }

func (w stalledLogWriter) Write(p []byte) (int, error) {
	<-w.release
	return 0, errors.New("output unavailable")
}

// A blocked terminal or failed pipe cannot block local requests or change results.
func TestRuntimeLogsCannotBlockAuthorizationResponse(t *testing.T) {
	writer := stalledLogWriter{release: make(chan struct{})}
	logs := NewRuntimeLogs(writer)
	defer func() { close(writer.release); logs.Shutdown(context.Background()) }()
	telemetry, _ := NewTelemetry(context.Background(), "")
	telemetry.WithRuntimeLogs(logs)
	handler := telemetry.WrapHTTP("evaluate", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	completed := make(chan bool, 1)
	go func() {
		for i := 0; i < 1024; i++ {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/evaluate", nil))
			telemetry.logs.RecordServiceEvent("configuration_sync_failed")
			if response.Code != http.StatusForbidden {
				completed <- false
				return
			}
		}
		completed <- true
	}()
	select {
	case ok := <-completed:
		if !ok || logs.Dropped() == 0 {
			t.Fatal("response changed or full log queue was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("log writer blocked requests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	logs.Shutdown(ctx)
}
