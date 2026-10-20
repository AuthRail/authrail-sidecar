package sidecar

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const ledgerReadVersionID = "00000000-0000-4000-8000-000000000090"
const ledgerTargetRequestID = "00000000-0000-4000-8000-000000000091"

func ledgerDecision(t *testing.T, syncer *Synchronizer, request EvaluationRequest) Evaluation {
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
	EvaluationHandler(syncer, "abcdefghijklmnopqrstuvwxyz012345").ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("evaluation failed with HTTP %d: %s", response.Code, response.Body.String())
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil {
		t.Fatal(err)
	}
	return evaluation
}

func ledgerSynchronizer(t *testing.T) *Synchronizer {
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
	return decisionSynchronizer(t, []map[string]any{guard, policy, readRail})
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
	syncer := ledgerSynchronizer(t)
	request := call(50)
	request.RequestID = ledgerTargetRequestID
	request.Trajectory = &TrajectorySnapshot{SessionID: request.Attribution.SessionID,
		Complete: true, PriorReadOperationVersionIDs: []string{}}
	if result := ledgerDecision(t, syncer, request); result.Coverage != "unavailable" {
		t.Fatalf("missing start was trusted: %+v", result)
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
