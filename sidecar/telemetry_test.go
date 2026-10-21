package sidecar

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestTelemetryExportsRedactedSpanWithRemoteParent(t *testing.T) {
	traceBodies := make(chan []byte, 2)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/traces" {
			body, _ := io.ReadAll(r.Body)
			traceBodies <- body
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	telemetry, err := NewTelemetry(context.Background(), collector.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer telemetry.Shutdown(context.Background())
	handler := telemetry.WrapHTTP("evaluate", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/evaluate?secret=must-not-export", nil)
	request.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	request.Header.Set("Authorization", "Bearer must-not-export")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	select {
	case body := <-traceBodies:
		var export collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &export); err != nil {
			t.Fatal(err)
		}
		spans := export.ResourceSpans[0].ScopeSpans[0].Spans
		if len(spans) != 1 || string(spans[0].TraceId) != string([]byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) ||
			string(spans[0].ParentSpanId) != string([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) {
			t.Fatalf("remote trace context was not preserved: %+v", spans)
		}
		if containsBytes(body, []byte("must-not-export")) {
			t.Fatal("request credentials or URL leaked into telemetry")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("span was not exported")
	}
}

func TestTelemetryCollectorFailureDoesNotDelayHandler(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/traces" {
			time.Sleep(800 * time.Millisecond)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer collector.Close()
	telemetry, err := NewTelemetry(context.Background(), collector.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer telemetry.Shutdown(context.Background())
	handler := telemetry.WrapHTTP("evaluate", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	started := time.Now()
	for i := 0; i < telemetryQueueSize+64; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/evaluate", nil))
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("collector blocked decisions for %v", elapsed)
	}
	deadline := time.After(3 * time.Second)
	for telemetry.Failures() == 0 {
		select {
		case <-deadline:
			t.Fatal("bounded queue did not expose dropped telemetry")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
