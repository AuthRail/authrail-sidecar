package sidecar

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The local evaluation listener returns permission, never executes a business effect.
// This fixture keeps the provider credential behind a separate protected executor.
func TestRawHTTPDecisionAndProtectedEffectBoundary(t *testing.T) {
	const adapterToken = "abcdefghijklmnopqrstuvwxyz012345"
	const providerToken = "protected-provider-secret"
	const actionID = "00000000-0000-4000-8000-000000000020"
	const certificateID = "00000000-0000-4000-8000-000000000021"
	const attemptID = "00000000-0000-4000-8000-000000000022"
	const receiptID = "00000000-0000-4000-8000-000000000023"
	guard := decisionRail("00000000-0000-4000-8000-000000000010",
		"00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
			"id": "large", "phase": "tool_call", "when": decisionCondition("gt", 100),
			"outcome": "deny"}})
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "phase": "tool_call", "when": decisionCondition("lte", 100),
			"outcome": "allow"}})
	policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
	syncer := decisionSynchronizerMode(t, []map[string]any{guard, policy}, "enforce")
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer deployment-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/runtime/deployment/observations":
			if r.Header.Get("Idempotency-Key") == "unavailable-1" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			replayed := r.Header.Get("Idempotency-Key") == "replayed-1"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"actionId": actionID, "certificateId": certificateID, "replayed": replayed})
		case "/runtime/deployment/execution-receipts":
			var receipt executionReceipt
			if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil ||
				receipt.ActionID != actionID || receipt.AttemptID != attemptID ||
				receipt.Event != "started" ||
				r.Header.Get("Idempotency-Key") != actionID+":"+attemptID+":started" {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"receiptId": receiptID, "state": "executing", "replayed": false})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer control.Close()
	syncer.options.ControlPlaneURL = control.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = control.Client()
	listener := EvaluationHandler(syncer, adapterToken)
	effects := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+providerToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		effects++
		w.WriteHeader(http.StatusCreated)
	}))
	defer provider.Close()

	// The agent can invoke the provider endpoint but cannot authenticate as the executor.
	agentRequest, _ := http.NewRequest(http.MethodPost, provider.URL, nil)
	agentResponse, err := provider.Client().Do(agentRequest)
	if err != nil {
		t.Fatal(err)
	}
	agentResponse.Body.Close()
	if agentResponse.StatusCode != http.StatusUnauthorized || effects != 0 {
		t.Fatalf("agent reached provider effect: HTTP %d, effects %d", agentResponse.StatusCode, effects)
	}

	evaluate := func(request EvaluationRequest, signedActionKey, sentActionKey, token string) (int, Evaluation) {
		t.Helper()
		encoded, err := json.Marshal(signedCall(t, syncer, request, signedActionKey))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
		httpRequest.Header.Set("Authorization", "Bearer "+token)
		httpRequest.Header.Set("Idempotency-Key", sentActionKey)
		response := httptest.NewRecorder()
		listener.ServeHTTP(response, httpRequest)
		var decision Evaluation
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
				t.Fatal(err)
			}
		}
		return response.Code, decision
	}
	allowed := func(status int, decision Evaluation) bool {
		return status == http.StatusOK && decision.Mode == "enforce" &&
			decision.Coverage == "evaluated" && decision.Outcome == "allow" &&
			!decision.Enforced && decision.BundleID != nil && *decision.BundleID == bundleID &&
			decision.RecordingStatus == "retained" && decision.ActionID == actionID &&
			decision.CertificateID == certificateID && decision.ReportReplayed != nil &&
			!*decision.ReportReplayed
	}
	invokeExecutor := func(status int, decision Evaluation) {
		t.Helper()
		if !allowed(status, decision) {
			return
		}
		receipt := executionReceipt{ActionID: decision.ActionID, AttemptID: attemptID,
			Event: "started", InputSHA256: strings.Repeat("a", 64),
			ProviderIdempotencyKey: "ar-allow-1", KeySHA256: strings.Repeat("b", 64),
			Proof: IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "fixture-proof"}}
		body, _ := json.Marshal(receipt)
		start := httptest.NewRequest(http.MethodPost, "/execution-receipts", bytes.NewReader(body))
		start.Header.Set("Authorization", "Bearer "+adapterToken)
		start.Header.Set("Idempotency-Key", actionID+":"+attemptID+":started")
		ack := httptest.NewRecorder()
		ExecutionReceiptHandler(syncer, adapterToken).ServeHTTP(ack, start)
		var retained struct {
			ReceiptID string `json:"receiptId"`
			State     string `json:"state"`
			Replayed  bool   `json:"replayed"`
		}
		if ack.Code != http.StatusCreated || json.Unmarshal(ack.Body.Bytes(), &retained) != nil ||
			retained.ReceiptID != receiptID || retained.State != "executing" || retained.Replayed {
			t.Fatalf("fresh started receipt was not retained: HTTP %d, %+v", ack.Code, retained)
		}
		request, _ := http.NewRequest(http.MethodPost, provider.URL, nil)
		request.Header.Set("Authorization", "Bearer "+providerToken)
		response, err := provider.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("protected executor failed: HTTP %d", response.StatusCode)
		}
	}

	for _, candidate := range []struct {
		name, signedKey, sentKey, token string
		request                         EvaluationRequest
		wantStatus                      int
		wantOutcome                     string
	}{
		{"deny", "deny-1", "deny-1", adapterToken, call(150), http.StatusOK, "deny"},
		{"missing adapter credential", "no-token", "no-token", "wrong-token", call(80), http.StatusUnauthorized, ""},
		{"proof replay under another action", "replay-1", "replay-2", adapterToken, call(80), http.StatusUnauthorized, ""},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			status, decision := evaluate(candidate.request, candidate.signedKey, candidate.sentKey, candidate.token)
			if status != candidate.wantStatus || decision.Outcome != candidate.wantOutcome || decision.Enforced {
				t.Fatalf("unexpected decision: HTTP %d %+v", status, decision)
			}
			invokeExecutor(status, decision)
			if effects != 0 {
				t.Fatalf("blocked attempt produced %d effects", effects)
			}
		})
	}

	// A valid signature cannot be reused after changing the authenticated principal.
	changed := signedCall(t, syncer, call(80), "identity-1")
	changed.Attribution.PrincipalID = "other_staff"
	encoded, _ := json.Marshal(changed)
	httpRequest := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
	httpRequest.Header.Set("Authorization", "Bearer "+adapterToken)
	httpRequest.Header.Set("Idempotency-Key", "identity-1")
	response := httptest.NewRecorder()
	listener.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusUnauthorized || effects != 0 {
		t.Fatalf("changed identity reached provider: HTTP %d, effects %d", response.Code, effects)
	}

	for _, candidate := range []struct {
		key, recording string
		replayed       bool
	}{
		{"unavailable-1", "queued", false},
		{"replayed-1", "retained", true},
	} {
		status, decision := evaluate(call(80), candidate.key, candidate.key, adapterToken)
		if status != http.StatusOK || decision.RecordingStatus != candidate.recording ||
			(candidate.replayed && (decision.ReportReplayed == nil || !*decision.ReportReplayed)) ||
			allowed(status, decision) {
			t.Fatalf("unretained or replayed report authorized an effect: HTTP %d, %+v", status, decision)
		}
		invokeExecutor(status, decision)
		if effects != 0 {
			t.Fatalf("unretained or replayed report caused %d effects", effects)
		}
	}

	status, decision := evaluate(call(80), "allow-1", "allow-1", adapterToken)
	if !allowed(status, decision) || decision.Enforced || effects != 0 {
		t.Fatalf("sidecar response claimed or caused execution: HTTP %d, %+v, effects %d", status, decision, effects)
	}
	invokeExecutor(status, decision)
	if effects != 1 {
		t.Fatalf("protected executor did not own the effect: %d", effects)
	}
	result := call(80)
	result.Phase = "tool_result"
	result.Result = json.RawMessage(`{"status":"created"}`)
	status, decision = evaluate(result, "allow-1", "allow-1", adapterToken)
	if status != http.StatusOK || decision.Coverage != "evaluated" || decision.Enforced || effects != 1 {
		t.Fatalf("signed result hook claimed or repeated execution: HTTP %d, %+v, effects %d", status, decision, effects)
	}

	// Once the signed bundle expires, even a fresh executor proof cannot authorize.
	syncer.options.Now = func() time.Time { return time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC) }
	status, decision = evaluate(call(80), "stale-1", "stale-1", adapterToken)
	if status != http.StatusOK || decision.Coverage != "unavailable" || allowed(status, decision) {
		t.Fatalf("expired bundle authorized effect: HTTP %d, %+v", status, decision)
	}
	invokeExecutor(status, decision)
	if effects != 1 {
		t.Fatalf("expired bundle caused another effect: %d", effects)
	}
}
