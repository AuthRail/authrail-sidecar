package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClosedKeyReportBecomesVisibleLocalGap(t *testing.T) {
	syncer := decisionSynchronizer(t, nil)
	entry := queuedObserve{ActionKey: "closed-key", Phase: "tool_call",
		Body: json.RawMessage(`{"formatVersion":1,"inputSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attribution":{"principalId":"staff_123","sessionId":"task_123","resourceId":null},"report":{"operationVersionId":"00000000-0000-4000-8000-000000000008","phase":"tool_call","evaluation":{"requestId":"old"}}}`)}
	if _, err := syncer.enqueueObserve(entry); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"EXECUTOR_KEY_CLOSED","message":"The application key no longer accepts reports."}`))
	}))
	defer server.Close()
	syncer.options.ControlPlaneURL = server.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = server.Client()
	if err := syncer.RetryObservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if syncer.Snapshot().PendingReports != 0 || syncer.Snapshot().BlockedReports != 1 {
		t.Fatal("closed-key report was not kept as a visible gap")
	}
	restarted := &Synchronizer{options: syncer.options, state: syncer.state}
	if err := restarted.RetryObservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || restarted.Snapshot().BlockedReports != 1 {
		t.Fatal("closed-key report was retried or lost after restart")
	}
}

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

func TestEnforceDecisionReportsBothPhasesWithoutExecutionClaim(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100), "outcome": "allow"}})
	policy["operationContract"] = map[string]any{"requiredCoverage": []string{"tool_call", "tool_result"}}
	syncer := decisionSynchronizerMode(t, []map[string]any{policy}, "enforce")
	var phases []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Report struct {
				Phase      string     `json:"phase"`
				Evaluation Evaluation `json:"evaluation"`
			} `json:"report"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		phases = append(phases, body.Report.Phase)
		if body.Report.Evaluation.Mode != "enforce" || body.Report.Evaluation.Enforced ||
			body.Report.Evaluation.Outcome != "allow" {
			t.Errorf("Enforce report overstated the local decision: %+v", body.Report.Evaluation)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"actionId":"00000000-0000-4000-8000-000000000020","certificateId":"00000000-0000-4000-8000-000000000021","replayed":false}`))
	}))
	defer server.Close()
	syncer.options.ControlPlaneURL = server.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = server.Client()
	for _, phase := range []string{"tool_call", "tool_result"} {
		requestValue := call(50)
		requestValue.Phase = phase
		if phase == "tool_result" {
			requestValue.Result = json.RawMessage(`{"status":"ok"}`)
		}
		requestValue = signedCall(t, syncer, requestValue, "invoice-123")
		encoded, _ := json.Marshal(requestValue)
		request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
		request.Header.Set("Idempotency-Key", "invoice-123")
		response := httptest.NewRecorder()
		EvaluationHandler(syncer, strings.Repeat("a", 32)).ServeHTTP(response, request)
		var decision Evaluation
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil ||
			decision.Mode != "enforce" || decision.Enforced || decision.RecordingStatus != "retained" ||
			decision.ReportReplayed == nil || *decision.ReportReplayed {
			t.Fatalf("local Enforce decision failed: %d %+v", response.Code, decision)
		}
	}
	if len(phases) != 2 || phases[0] != "tool_call" || phases[1] != "tool_result" {
		t.Fatalf("missing Enforce report phase: %v", phases)
	}
}

func TestObserveReportRetainsReviewedExtractionWithoutDocumentOrModelOutput(t *testing.T) {
	sourceVersionID := "00000000-0000-4000-8000-000000000130"
	dataVersionID := "00000000-0000-4000-8000-000000000131"
	data := decisionRail("00000000-0000-4000-8000-000000000132", dataVersionID, "data", nil)
	data["sourceContextVersionId"] = sourceVersionID
	data["sourceContextContract"] = map[string]any{
		"formatVersion": 5, "kind": "extraction", "sourceIdentity": "support.messages",
		"accountBoundary": "tenant_123", "lookup": "message.read",
		"queryField": map[string]any{"root": "arguments", "path": []string{"messageId"}},
		"factKey":    "sensitive", "resultPath": []string{"sensitive"}, "valueType": "boolean",
		"modelId": "model.v1", "modelConfigSha256": strings.Repeat("a", 64),
		"promptVersion": "prompt.v1", "maxInputBytes": 4096, "maxOutputBytes": 256,
		"maxAgeSeconds": 60, "timeoutMs": 2000, "failure": "unavailable"}
	policy := decisionRail("00000000-0000-4000-8000-000000000133",
		"00000000-0000-4000-8000-000000000134", "policy", []map[string]any{{
			"id": "ordinary", "when": map[string]any{"kind": "compare",
				"left":       map[string]any{"root": "facts", "path": []string{"sensitive"}},
				"comparison": "eq", "right": map[string]any{"kind": "literal", "value": false}},
			"outcome": "allow"}})
	policy["content"].(map[string]any)["factBindings"] = []map[string]any{{
		"factKey": "sensitive", "dataRailVersionId": dataVersionID}}
	syncer := decisionSynchronizer(t, []map[string]any{data, policy})
	request := call(50)
	request.Arguments = json.RawMessage(`{"messageId":"msg_123","privateText":"do not retain this"}`)
	request.FactResolutions = []FactResolution{{SourceVersionID: sourceVersionID,
		SourceIdentity: "support.messages", AccountBoundary: "tenant_123",
		Lookup: "message.read", LookupKey: "msg_123", AuthenticatedExecutor: true,
		Status: "ok", ObservedAt: syncer.options.Now().Add(-20 * time.Second).Format(time.RFC3339Nano),
		Value: map[string]any{"sensitive": false}, Extraction: &ExtractionProvenance{
			SourceSHA256: strings.Repeat("b", 64), SourceBytes: 120,
			SourceLocation: "message:msg_123", ModelID: "model.v1",
			ModelConfigSHA256: strings.Repeat("a", 64), PromptVersion: "prompt.v1",
			ExtractedAt: syncer.options.Now().Add(-10 * time.Second).Format(time.RFC3339Nano)}}}
	reports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reports++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if bytes.Contains(body, []byte("privateText")) || bytes.Contains(body, []byte("do not retain")) ||
			bytes.Contains(body, []byte(`"sensitive":false`)) {
			t.Error("document or model assertion reached the control plane")
		}
		var report struct {
			Report struct {
				Evaluation Evaluation `json:"evaluation"`
			} `json:"report"`
		}
		if err := json.Unmarshal(body, &report); err != nil ||
			len(report.Report.Evaluation.Facts) != 1 || report.Report.Evaluation.Facts[0].Extraction == nil ||
			report.Report.Evaluation.Facts[0].Extraction.SourceLocation != "message:msg_123" {
			t.Errorf("extraction provenance was not reported: %s", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"actionId":"00000000-0000-4000-8000-000000000020","certificateId":"00000000-0000-4000-8000-000000000021","replayed":false}`))
	}))
	defer server.Close()
	syncer.options.ControlPlaneURL = server.URL
	syncer.options.Token = "deployment-secret"
	syncer.options.Client = server.Client()
	requestBody, _ := json.Marshal(signedCall(t, syncer, request, "message-123"))
	httpRequest := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(requestBody))
	httpRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	httpRequest.Header.Set("Idempotency-Key", "message-123")
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, strings.Repeat("a", 32)).ServeHTTP(response, httpRequest)
	var evaluation Evaluation
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &evaluation) != nil ||
		evaluation.Outcome != "allow" || evaluation.RecordingStatus != "retained" || reports != 1 {
		t.Fatalf("signed extraction report was not retained: %d %+v, reports=%d", response.Code, evaluation, reports)
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
