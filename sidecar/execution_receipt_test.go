package sidecar

import (
	"bytes"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.URL.Path != "/runtime/deployment/execution-receipts" ||
			r.Header.Get("Authorization") != "Bearer deployment-secret" ||
			r.Header.Get("Idempotency-Key") != actionID+":"+attemptID+":started" {
			t.Errorf("wrong protected server request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receiptId": receiptID, "state": "executing", "replayed": false})
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
	handler := ExecutionReceiptHandler(syncer, strings.Repeat("c", 32))
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
}
