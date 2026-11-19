package sidecar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const ledgerReadVersionID = "00000000-0000-4000-8000-000000000090"
const ledgerTargetRequestID = "00000000-0000-4000-8000-000000000091"

func ledgerDecision(t *testing.T, syncer *Synchronizer, request EvaluationRequest, telemetry ...*Telemetry) Evaluation {
	t.Helper()
	actionKey := "invoice-123"
	encoded, err := json.Marshal(signedCall(t, syncer, request, actionKey))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
	httpRequest.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	httpRequest.Header.Set("Idempotency-Key", actionKey)
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, "abcdefghijklmnopqrstuvwxyz012345", telemetry...).ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("evaluation failed with HTTP %d: %s", response.Code, response.Body.String())
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil {
		t.Fatal(err)
	}
	return evaluation
}

func ledgerSynchronizer(t *testing.T, mode ...string) *Synchronizer {
	t.Helper()
	guard := decisionRail("00000000-0000-4000-8000-000000000092",
		"00000000-0000-4000-8000-000000000093", "guard", []map[string]any{{
			"id": "priorRead", "kind": "prior_read", "phase": "tool_call",
			"sourceOperationVersionId": ledgerReadVersionID, "outcome": "deny"}})
	guard["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "trajectory"}
	policy := decisionRail("00000000-0000-4000-8000-000000000094",
		"00000000-0000-4000-8000-000000000095", "policy", []map[string]any{{
			"id": "allow", "when": decisionCondition("gt", 0), "outcome": "allow"}})
	readRail := decisionRail("00000000-0000-4000-8000-000000000096",
		"00000000-0000-4000-8000-000000000097", "guard", []map[string]any{{
			"id": "readResult", "phase": "tool_result", "when": decisionCondition("gt", 0), "outcome": "allow"}})
	readRail["operationVersionId"] = ledgerReadVersionID
	readRail["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
	readRail["operationContract"].(map[string]any)["expectedEffects"] = []map[string]any{{"kind": "read"}}
	selectedMode := "observe"
	if len(mode) > 0 {
		selectedMode = mode[0]
	}
	return decisionSynchronizerMode(t, []map[string]any{guard, policy, readRail}, selectedMode)
}

func ledgerStart(t *testing.T, syncer *Synchronizer) EvaluationRequest {
	t.Helper()
	request := call(50)
	request.OperationVersionID = ledgerReadVersionID
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Start: true, Complete: true, PriorReadOperationVersionIDs: []string{}}
	if result := ledgerDecision(t, syncer, request); result.Coverage == "unavailable" {
		t.Fatalf("session start unavailable: %+v", result)
	}
	return request
}

func TestTrajectoryLedgerPersistsReadResultAndRejectsForgedHistory(t *testing.T) {
	syncer := ledgerSynchronizer(t)
	read := ledgerStart(t, syncer)
	read.Phase = "tool_result"
	read.Result = json.RawMessage(`{"status":"found"}`)
	if result := ledgerDecision(t, syncer, read); result.Coverage != "evaluated" {
		t.Fatalf("read result not covered: %+v", result)
	}
	if result := ledgerDecision(t, syncer, read); result.Coverage != "evaluated" {
		t.Fatalf("identical result replay failed: %+v", result)
	}
	replayedCall := read
	replayedCall.Phase = "tool_call"
	replayedCall.Result = nil
	if result := ledgerDecision(t, syncer, replayedCall); result.Coverage != "evaluated" {
		t.Fatalf("identical call replay after result failed: %+v", result)
	}
	request := call(50)
	request.RequestID = ledgerTargetRequestID
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Complete: true, PriorReadOperationVersionIDs: []string{ledgerReadVersionID}}
	if result := ledgerDecision(t, syncer, request); result.Outcome != "deny" {
		t.Fatalf("prior read did not deny: %+v", result)
	}
	request.Trajectory.PriorReadOperationVersionIDs = []string{}
	if result := ledgerDecision(t, syncer, request); result.Coverage != "unavailable" {
		t.Fatalf("omitted read history was trusted: %+v", result)
	}
	state, err := loadState(syncer.options.StateFile, organisationID, deploymentID)
	if err != nil || !state.TrajectoryLedgerStarted {
		t.Fatalf("ledger marker was not persisted: %+v %v", state, err)
	}
	restarted := &Synchronizer{options: syncer.options, state: state}
	request.Trajectory.PriorReadOperationVersionIDs = []string{ledgerReadVersionID}
	if result := ledgerDecision(t, restarted, request); result.Outcome != "deny" {
		t.Fatalf("restart lost read history: %+v", result)
	}
	data, err := os.ReadFile(restarted.trajectoryLedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	var changed trajectoryLedger
	if err := json.Unmarshal(data, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Sessions[0].Reads = []string{}
	modified, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restarted.trajectoryLedgerPath(), modified, 0600); err != nil {
		t.Fatal(err)
	}
	corrupted := &Synchronizer{options: syncer.options, state: state}
	if result := ledgerDecision(t, corrupted, request); result.Coverage != "unavailable" {
		t.Fatalf("inconsistent ledger was trusted: %+v", result)
	}
	if err := os.Remove(restarted.trajectoryLedgerPath()); err != nil {
		t.Fatal(err)
	}
	if result := ledgerDecision(t, restarted, request); result.Coverage != "unavailable" {
		t.Fatalf("running sidecar trusted missing ledger: %+v", result)
	}
	missing := &Synchronizer{options: syncer.options, state: state}
	if result := ledgerDecision(t, missing, request); result.Coverage != "unavailable" {
		t.Fatalf("deleted ledger was trusted: %+v", result)
	}
}

func TestTrajectoryLedgerRequiresSessionStartAndExactResultReplay(t *testing.T) {
	syncer := ledgerSynchronizer(t, "enforce")
	var output bytes.Buffer
	logs := NewRuntimeLogs(&output)
	telemetry := (&Telemetry{}).WithRuntimeLogs(logs)
	request := call(50)
	request.RequestID = ledgerTargetRequestID
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Complete: true, PriorReadOperationVersionIDs: []string{}}
	if result := ledgerDecision(t, syncer, request, telemetry); result.Coverage != "unavailable" || result.Mode != "observe" {
		t.Fatalf("unavailable wire fallback changed: %+v", result)
	}
	logs.Shutdown(context.Background())
	var event runtimeLogEvent
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "check_unavailable" || event.Mode != "enforce" || event.Phase != "tool_call" || event.RequestID != request.RequestID {
		t.Fatalf("trajectory diagnostics mislabelled the protected request: %+v", event)
	}
	read := ledgerStart(t, syncer)
	read.Phase = "tool_result"
	read.Result = json.RawMessage(`{"status":"found"}`)
	if result := ledgerDecision(t, syncer, read); result.Coverage != "evaluated" {
		t.Fatalf("read result not covered: %+v", result)
	}
	read.Result = json.RawMessage(`{"status":"changed"}`)
	if result := ledgerDecision(t, syncer, read); result.Coverage != "unavailable" {
		t.Fatalf("changed result replay was trusted: %+v", result)
	}
}

func TestTrajectoryLedgerRejectsReadResultWithoutMatchingCall(t *testing.T) {
	syncer := ledgerSynchronizer(t)
	ledgerStart(t, syncer)
	read := call(50)
	read.RequestID = "00000000-0000-4000-8000-000000000098"
	read.OperationVersionID = ledgerReadVersionID
	read.Phase = "tool_result"
	read.Result = json.RawMessage(`{"status":"found"}`)
	read.Trajectory = &TrajectorySnapshot{SessionID: read.Attribution.SessionID,
		Complete: true, PriorReadOperationVersionIDs: []string{}}
	if result := ledgerDecision(t, syncer, read); result.Coverage != "unavailable" {
		t.Fatalf("orphaned read result was trusted: %+v", result)
	}
	request := call(50)
	request.RequestID = ledgerTargetRequestID
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Complete: true, PriorReadOperationVersionIDs: []string{}}
	if result := ledgerDecision(t, syncer, request); result.Coverage != "unavailable" {
		t.Fatalf("history gap cleared a prior-read rule: %+v", result)
	}
}

func TestTrajectoryLedgerAppliesReviewedPriorActivityAndRejectsUnprovenEffects(t *testing.T) {
	guard := decisionRail("00000000-0000-4000-8000-000000000100",
		"00000000-0000-4000-8000-000000000101", "guard", []map[string]any{{
			"id": "sensitivePast", "phase": "tool_call", "outcome": "deny",
			"when": map[string]any{"kind": "compare",
				"left":       map[string]any{"root": "trajectory", "path": []string{"sensitiveDataSeen"}},
				"comparison": "eq", "right": map[string]any{"kind": "literal", "value": true}}}})
	guard["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "trajectory"}
	guard["operationContract"].(map[string]any)["availableFields"] = []map[string]any{{
		"root": "trajectory", "path": []string{"sensitiveDataSeen"}, "type": "boolean"}}
	policy := decisionRail("00000000-0000-4000-8000-000000000102",
		"00000000-0000-4000-8000-000000000103", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("gt", 0), "outcome": "allow"}})
	policy["operationContract"].(map[string]any)["availableFields"] =
		guard["operationContract"].(map[string]any)["availableFields"]
	syncer := decisionSynchronizer(t, []map[string]any{guard, policy})
	request := call(50)
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Start: true, Complete: true, PriorReadOperationVersionIDs: []string{},
		Values: map[string]any{"sensitiveDataSeen": true}}
	if result := ledgerDecision(t, syncer, request); result.Outcome != "deny" || result.Coverage != "evaluated" {
		t.Fatalf("reviewed prior activity was not applied: %+v", result)
	}
	request.RequestID = ledgerTargetRequestID
	request.Trajectory.Start = false
	request.Trajectory.Values = nil
	if result := ledgerDecision(t, syncer, request); result.Outcome != "additional_context_required" {
		t.Fatalf("missing prior activity was treated as clear: %+v", result)
	}
	request.Trajectory.Values = map[string]any{"unreviewedEffect": true}
	encoded, err := json.Marshal(signedCall(t, syncer, request, "invoice-123"))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
	httpRequest.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	httpRequest.Header.Set("Idempotency-Key", "invoice-123")
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, "abcdefghijklmnopqrstuvwxyz012345").ServeHTTP(response, httpRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unreviewed activity was accepted: %d", response.Code)
	}
	request.Trajectory.Values = nil
	encoded, err = json.Marshal(signedCall(t, syncer, request, "invoice-123"))
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte("{"),
		[]byte(`{"priorEffects":[{"kind":"write"}],`), 1)
	httpRequest = httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(encoded))
	httpRequest.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	httpRequest.Header.Set("Idempotency-Key", "invoice-123")
	response = httptest.NewRecorder()
	EvaluationHandler(syncer, "abcdefghijklmnopqrstuvwxyz012345").ServeHTTP(response, httpRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unproven prior effects were accepted: %d", response.Code)
	}
}

// The original call and current result keep their own bundle identities. Only
// central Enforce retention may establish the cross-renewal link.
func TestTrajectoryRenewalRequiresRetainedCurrentAuthority(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "retained"}[accepted], func(t *testing.T) {
			syncer := ledgerSynchronizer(t, "enforce")
			read := ledgerStart(t, syncer)
			newBundle := "00000000-0000-4000-8000-000000000099"
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(syncer.state.Current.Bundle.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if json.Unmarshal(raw, &manifest) != nil {
				t.Fatal("invalid fixture bundle")
			}
			manifest["bundleId"], manifest["sequence"] = newBundle, 2
			raw, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			pin := sha256.Sum256(der)
			config := *syncer.state.Current
			signed := *config.Bundle
			config.Bundle = &signed
			signed.Payload, signed.Signature = base64.RawURLEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(signature)
			signed.VerificationKey.Base64, signed.VerificationKey.SHA256 = base64.StdEncoding.EncodeToString(der), hex.EncodeToString(pin[:])
			config.Deployment.ActiveBundleID, config.Deployment.Sequence = &newBundle, 2
			syncer.options.TrustedPins = map[string]struct{}{hex.EncodeToString(pin[:]): {}}
			syncer.state.Current, syncer.state.Floor = &config, 2
			read.Phase, read.Result = "tool_result", json.RawMessage(`{"status":"found"}`)
			read.Trajectory.verified = true
			evaluation, err := syncer.Evaluate(read)
			if err != nil {
				t.Fatal(err)
			}
			if err := syncer.recordTrajectoryResultLocked(read, "invoice-123", evaluation); !errors.Is(err, errTrajectoryRenewal) {
				t.Fatalf("cross-bundle result skipped central authority: %v", err)
			}
			if len(syncer.trajectoryState.Sessions[0].Results) != 0 {
				t.Fatal("unproven result saved")
			}
			reports := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reports++
				if r.URL.Path != "/runtime/deployment/observations" {
					t.Error("unexpected remote path")
				}
				if !accepted {
					w.WriteHeader(http.StatusConflict)
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"actionId":"00000000-0000-4000-8000-000000000020","certificateId":"00000000-0000-4000-8000-000000000021","replayed":false}`))
			}))
			defer upstream.Close()
			syncer.options.ControlPlaneURL, syncer.options.Token, syncer.options.Client = upstream.URL, "deployment-token", upstream.Client()
			result := ledgerDecision(t, syncer, read)
			if reports != 1 {
				t.Fatalf("unexpected retention count: %d", reports)
			}
			session := syncer.trajectoryState.Sessions[0]
			if !accepted {
				if result.Coverage != "unavailable" || !session.Gap || len(session.Results) != 0 {
					t.Fatal("failed retention created history")
				}
				return
			}
			if result.RecordingStatus != "retained" || len(session.Results) != 1 || session.Gap {
				t.Fatalf("retained result missing: %+v", result)
			}
			saved := session.Results[0]
			if saved.BundleID != newBundle || saved.Sequence != 2 || saved.CallBundleID != bundleID || saved.CallSequence != 1 || saved.ResultCertificateID == "" {
				t.Fatalf("historical bundles rewritten: %+v", saved)
			}
			restarted := &Synchronizer{options: syncer.options, state: syncer.state}
			if err := restarted.loadTrajectoryLedgerLocked(); err != nil {
				t.Fatalf("proven link lost on restart: %v", err)
			}
			changed := read
			changed.Arguments = json.RawMessage(`{"amount":70}`)
			if err := restarted.recordTrajectoryResultLocked(changed, "invoice-123", evaluation, saved.ResultCertificateID); err == nil {
				t.Fatal("changed result reused retained link")
			}
			if err := restarted.recordTrajectoryResultLocked(read, "foreign-key", evaluation, saved.ResultCertificateID); err == nil {
				t.Fatal("foreign business identity linked")
			}
		})
	}
}
