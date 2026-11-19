package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecutionReceiptRequiresAdapterAndForwardsOnce(t *testing.T) {
	const actionID = "00000000-0000-4000-8000-000000000001"
	const attemptID = "00000000-0000-4000-8000-000000000002"
	const receiptID = "00000000-0000-4000-8000-000000000003"
	posts := 0
	reject := false
	responseSuffix := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if reject {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if r.URL.Path != "/runtime/deployment/execution-receipts" ||
			r.Header.Get("Authorization") != "Bearer deployment-secret" ||
			r.Header.Get("Idempotency-Key") != actionID+":"+attemptID+":started" {
			t.Errorf("wrong protected server request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receiptId": receiptID, "state": "executing", "replayed": false})
		_, _ = w.Write([]byte(responseSuffix))
	}))
	defer server.Close()
	syncer := &Synchronizer{options: Options{ControlPlaneURL: server.URL,
		Token: "deployment-secret", Client: server.Client()}}
	receipt := executionReceipt{ActionID: actionID, AttemptID: attemptID,
		Event: "started", InputSHA256: strings.Repeat("a", 64),
		ProviderIdempotencyKey: "ar-" + actionID,
		KeySHA256:              strings.Repeat("b", 64),
		Proof:                  IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "signature"}}
	body, _ := json.Marshal(receipt)
	var output bytes.Buffer
	logs := NewRuntimeLogs(&output)
	telemetry, _ := NewTelemetry(context.Background(), "")
	telemetry.WithRuntimeLogs(logs)
	handler := ExecutionReceiptHandler(syncer, strings.Repeat("c", 32), telemetry)
	request := httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || posts != 0 {
		t.Fatalf("unauthenticated receipt reached control plane: %d %d", response.Code, posts)
	}
	request = httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
	request.Header.Set("Idempotency-Key", actionID+":"+attemptID+":started")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || posts != 1 {
		t.Fatalf("receipt was not forwarded exactly once: %d %d", response.Code, posts)
	}
	for _, suffix := range []string{`{}`, strings.Repeat(" ", 2048)} {
		responseSuffix = suffix
		request = httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
		request.Header.Set("Idempotency-Key", actionID+":"+attemptID+":started")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("invalid control-plane receipt prefix accepted: HTTP %d", response.Code)
		}
	}
	// Rejected forwarding must not manufacture a retained execution log.
	reject = true
	request = httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
	request.Header.Set("Idempotency-Key", actionID+":"+attemptID+":started")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	logs.Shutdown(context.Background())
	if response.Code != http.StatusConflict || strings.Count(output.String(), `"event":"execution_report"`) != 1 ||
		!strings.Contains(output.String(), `"executionEvent":"started"`) || strings.Contains(output.String(), "deployment-secret") {
		t.Fatal("execution log misrepresented a rejected report or disclosed credentials")
	}

}

func TestReceiptOpaqueProviderReferenceIsBoundedAndForwardedUnchanged(t *testing.T) {
	const actionID = "00000000-0000-4000-8000-000000000001"
	const attemptID = "00000000-0000-4000-8000-000000000002"
	reference := "projects/acme/jobs/" + strings.Repeat(`"`, 3981)
	posts := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		var receipt executionReceipt
		if json.NewDecoder(r.Body).Decode(&receipt) != nil || receipt.ProviderReference == nil || *receipt.ProviderReference != reference {
			t.Error("opaque identity changed")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"receiptId":"00000000-0000-4000-8000-000000000003","state":"succeeded","replayed":false}`))
	}))
	defer upstream.Close()
	syncer := &Synchronizer{options: Options{ControlPlaneURL: upstream.URL, Token: "deployment-secret", Client: upstream.Client()}}
	receipt := executionReceipt{ActionID: actionID, AttemptID: attemptID, Event: "reconciled_succeeded", InputSHA256: strings.Repeat("a", 64), ProviderIdempotencyKey: "original-key", ProviderReference: &reference, KeySHA256: strings.Repeat("b", 64), Proof: IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "signature"}}
	invoke := func() int {
		body, _ := json.Marshal(receipt)
		request := httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer adapter-token")
		request.Header.Set("Idempotency-Key", actionID+":"+attemptID+":"+receipt.Event)
		response := httptest.NewRecorder()
		ExecutionReceiptHandler(syncer, "adapter-token").ServeHTTP(response, request)
		return response.Code
	}
	if status := invoke(); status != 201 || posts != 1 {
		t.Fatalf("bounded escaped reference rejected: %d %d", status, posts)
	}
	for _, invalid := range []string{"", " padded", "trailing ", "line\nbreak", strings.Repeat("é", 2001)} {
		receipt.ProviderReference = &invalid
		if status := invoke(); status != 400 || posts != 1 {
			t.Fatalf("invalid reference forwarded: %d %d", status, posts)
		}
	}
	receipt.ProviderReference = &reference
	receipt.Event = "started"
	if status := invoke(); status != 400 || posts != 1 {
		t.Fatal("start carried a provider reference")
	}
	receipt.Event = "reconciled_succeeded"
	receipt.ProviderReference = nil
	if status := invoke(); status != 400 || posts != 1 {
		t.Fatal("reconciliation lacked original provider identity")
	}
}
