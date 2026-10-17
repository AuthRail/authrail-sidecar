package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestObserveReportRetainsDigestWithoutToolPayload(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100),
			"outcome": "allow", "reason": "Ordinary amount"}})
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runtime/deployment/observations" ||
			r.Header.Get("Authorization") != "Bearer deployment-secret" ||
			r.Header.Get("Idempotency-Key") != "invoice-123" {
			t.Errorf("report audience or identity is wrong")
		}
		var body struct {
			InputSHA256          string               `json:"inputSha256"`
			IdentityVerification IdentityVerification `json:"identityVerification"`
			ExecutorProof        IdentityProof        `json:"executorProof"`
			Report               struct {
				Evaluation Evaluation `json:"evaluation"`
			} `json:"report"`
		}
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(r.Body); err != nil {
			t.Error(err)
		}
		if strings.Contains(raw.String(), "amount") || strings.Contains(raw.String(), "arguments") {
			t.Error("tool payload reached the control plane")
		}
		if err := json.Unmarshal(raw.Bytes(), &body); err != nil {
			t.Error(err)
		}
		input, err := observeInputBytes(call(50))
		if err != nil {
			t.Error(err)
		}
		expected := sha256.Sum256(input)
		if body.InputSHA256 != hex.EncodeToString(expected[:]) ||
			len(body.IdentityVerification.KeySHA256) != 64 ||
			len(body.IdentityVerification.SignatureSHA256) != 64 ||
			body.ExecutorProof.Signature == "" ||
			body.Report.Evaluation.Outcome != "allow" || body.Report.Evaluation.Enforced {
			t.Errorf("incorrect advisory report: %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"actionId":"00000000-0000-4000-8000-000000000020","certificateId":"00000000-0000-4000-8000-000000000021","replayed":false}`))
	}))
	defer server.Close()
	syncer.options.ControlPlaneURL = server.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = server.Client()
	requestBody, _ := json.Marshal(signedCall(t, syncer, call(50), "invoice-123"))
	request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	request.Header.Set("Idempotency-Key", "invoice-123")
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, strings.Repeat("a", 32)).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local evaluation failed: %d", response.Code)
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil {
		t.Fatal(err)
	}
	if evaluation.RecordingStatus != "retained" || evaluation.ActionID == "" ||
		evaluation.CertificateID == "" {
		t.Fatalf("retained report was not disclosed: %+v", evaluation)
	}
}

func TestObserveRecordingFailureKeepsLocalDecision(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100),
			"outcome": "allow", "reason": "Ordinary amount"}})
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	requestBody, _ := json.Marshal(signedCall(t, syncer, call(50), "invoice-123"))
	request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	request.Header.Set("Idempotency-Key", "invoice-123")
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, strings.Repeat("a", 32)).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local evaluation failed: %d", response.Code)
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil {
		t.Fatal(err)
	}
	if evaluation.Outcome != "allow" || evaluation.Enforced ||
		evaluation.RecordingStatus != "unavailable" || evaluation.ActionID != "" {
		t.Fatalf("recording failure changed the advisory result: %+v", evaluation)
	}
}

func TestObserveReportSurvivesRestartAndRetriesWithoutToolPayload(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100),
			"outcome": "allow", "reason": "Ordinary amount"}})
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	syncer.options.ControlPlaneURL = unavailable.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = unavailable.Client()
	requestBody, _ := json.Marshal(signedCall(t, syncer, call(50), "invoice-123"))
	request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	request.Header.Set("Idempotency-Key", "invoice-123")
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, strings.Repeat("a", 32)).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local decision failed: %d", response.Code)
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil {
		t.Fatal(err)
	}
	if evaluation.RecordingStatus != "queued" || syncer.Snapshot().PendingReports != 1 {
		t.Fatalf("failed report was not queued: %+v", evaluation)
	}
	unavailable.Close()
	data, err := os.ReadFile(syncer.observeQueuePath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("amount")) || bytes.Contains(data, []byte("arguments")) ||
		bytes.Contains(data, []byte("deployment-secret")) {
		t.Fatal("tool input or deployment credential was stored in the retry queue")
	}
	accepted := 0
	recovered := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted++
		if r.Header.Get("Idempotency-Key") != "invoice-123" {
			t.Error("action key changed on retry")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"actionId":"00000000-0000-4000-8000-000000000020","certificateId":"00000000-0000-4000-8000-000000000021","replayed":false}`))
	}))
	defer recovered.Close()
	restarted := &Synchronizer{options: syncer.options, state: syncer.state}
	restarted.options.ControlPlaneURL = recovered.URL
	restarted.options.Client = recovered.Client()
	if err := restarted.RetryObservations(request.Context()); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 || restarted.Snapshot().PendingReports != 0 {
		t.Fatalf("restart did not drain queued report: accepted=%d pending=%d", accepted,
			restarted.Snapshot().PendingReports)
	}
}

func TestObserveQueueRejectsChangedReportForSameActionAndPhase(t *testing.T) {
	syncer := decisionSynchronizer(t, nil)
	first := queuedObserve{ActionKey: "same-action", Phase: "tool_call",
		Body: json.RawMessage(`{"formatVersion":1,"inputSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attribution":{"principalId":"staff_123","sessionId":"task_123","resourceId":null},"report":{"operationVersionId":"00000000-0000-4000-8000-000000000008","phase":"tool_call","evaluation":{"requestId":"old"}}}`)}
	if _, err := syncer.enqueueObserve(first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.Body = bytes.Replace(first.Body, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 1)
	if _, err := syncer.enqueueObserve(changed); err == nil {
		t.Fatal("changed report replaced a durable action report")
	}
	newRequest := first
	newRequest.Body = bytes.Replace(first.Body, []byte(`"requestId":"old"`),
		[]byte(`"requestId":"new"`), 1)
	queued, err := syncer.enqueueObserve(newRequest)
	if err != nil || !bytes.Equal(queued.Body, first.Body) {
		t.Fatal("same action retry did not reuse its queued report")
	}
	syncer.observeQueue.Entries = make([]queuedObserve, maxObserveReports)
	full := first
	full.ActionKey = "new-action"
	if _, err := syncer.enqueueObserve(full); err == nil ||
		len(syncer.observeQueue.Entries) != maxObserveReports {
		t.Fatal("full queue silently replaced or accepted a report")
	}
}
