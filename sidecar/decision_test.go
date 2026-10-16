package sidecar

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

const decisionOperationID = "00000000-0000-4000-8000-000000000008"
const decisionRequestID = "00000000-0000-4000-8000-000000000009"

func decisionCondition(comparison string, value any) map[string]any {
	return map[string]any{"kind": "compare",
		"left":       map[string]any{"root": "arguments", "path": []string{"amount"}},
		"comparison": comparison,
		"right":      map[string]any{"kind": "literal", "value": value}}
}

func decisionRail(id, version, kind string, rules []map[string]any) map[string]any {
	return map[string]any{
		"railId": id, "versionId": version, "operationVersionId": decisionOperationID,
		"kind": kind, "operationContract": map[string]any{"requiredCoverage": []string{"tool_call"}},
		"content": map[string]any{"formatVersion": 2, "rules": rules},
	}
}

func decisionSynchronizer(t *testing.T, rails []map[string]any) *Synchronizer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	manifest := map[string]any{
		"formatVersion": 1, "bundleId": bundleID,
		"organisationId": organisationID, "deploymentId": deploymentID,
		"inventoryItemId": itemID, "inventoryRevisionId": revisionID,
		"sequence": 1, "mode": "observe",
		"issuedAt":   now.Add(-time.Minute).Format("2006-01-02T15:04:05.000Z"),
		"activeFrom": now.Add(-time.Minute).Format("2006-01-02T15:04:05.000Z"),
		"expiresAt":  now.Add(time.Hour).Format("2006-01-02T15:04:05.000Z"),
		"rails":      rails,
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	config := Configuration{}
	config.Deployment.OrganisationID = organisationID
	config.Deployment.DeploymentID = deploymentID
	config.Deployment.InventoryItemID = itemID
	config.Deployment.InventoryRevision = revisionID
	config.Deployment.Mode = "observe"
	config.Deployment.Sequence = 1
	config.Deployment.ActiveBundleID = pointer(bundleID)
	config.Bundle = &SignedBundle{Payload: base64.RawURLEncoding.EncodeToString(payload),
		KeyID: "test-key", Algorithm: "ECDSA_SHA_256",
		Signature: base64.StdEncoding.EncodeToString(signature)}
	config.Bundle.VerificationKey.Format = "spki-der"
	config.Bundle.VerificationKey.Base64 = base64.StdEncoding.EncodeToString(der)
	config.Bundle.VerificationKey.SHA256 = hex.EncodeToString(fingerprint[:])
	return &Synchronizer{options: Options{OrganisationID: organisationID,
		DeploymentID: deploymentID, TrustedPins: map[string]struct{}{config.Bundle.VerificationKey.SHA256: {}},
		StateFile: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return now }},
		state: diskState{FormatVersion: 1, OrganisationID: organisationID,
			DeploymentID: deploymentID, Floor: 1, Current: &config}}
}

func call(amount int) EvaluationRequest {
	args, _ := json.Marshal(map[string]any{"amount": amount})
	return EvaluationRequest{FormatVersion: 1, RequestID: decisionRequestID,
		OperationVersionID: decisionOperationID, Phase: "tool_call", Arguments: args}
}

func TestObserveCompositionKeepsGuardAndPolicyDistinct(t *testing.T) {
	guard := decisionRail("00000000-0000-4000-8000-000000000010",
		"00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
			"id": "large", "phase": "tool_call", "when": decisionCondition("gt", 100),
			"outcome": "deny", "reason": "Too large"}})
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100),
			"outcome": "allow", "reason": "Ordinary amount"}})
	syncer := decisionSynchronizer(t, []map[string]any{guard, policy})
	denied, err := syncer.Evaluate(call(101))
	if err != nil || denied.Outcome != "deny" || denied.Enforced || denied.Coverage != "evaluated" {
		t.Fatalf("Guard denial lost in Observe: %+v %v", denied, err)
	}
	allowed, err := syncer.Evaluate(call(50))
	if err != nil || allowed.Outcome != "allow" || allowed.Enforced || len(allowed.RailVersionIDs) != 2 {
		t.Fatalf("Policy allowance did not compose: %+v %v", allowed, err)
	}
	guardOnly := decisionSynchronizer(t, []map[string]any{guard})
	noBusinessAuthority, err := guardOnly.Evaluate(call(50))
	if err != nil || noBusinessAuthority.Outcome != "indeterminate" {
		t.Fatalf("Guard alone authorized a call: %+v %v", noBusinessAuthority, err)
	}
}

func TestObserveMissingFactsAndCoverage(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "trustedFact", "when": map[string]any{"kind": "compare",
				"left":       map[string]any{"root": "facts", "path": []string{"invoiceStatus"}},
				"comparison": "eq", "right": map[string]any{"kind": "literal", "value": "paid"}},
			"outcome": "allow", "reason": "Invoice is paid"}})
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	missing, err := syncer.Evaluate(call(50))
	if err != nil || missing.Outcome != "additional_context_required" ||
		len(missing.Unresolved) != 1 || missing.Unresolved[0].Reason != "unavailable" {
		t.Fatalf("untrusted fact authorized a call: %+v %v", missing, err)
	}
	unknown := call(50)
	unknown.OperationVersionID = "00000000-0000-4000-8000-000000000099"
	uncovered, err := syncer.Evaluate(unknown)
	if err != nil || uncovered.Coverage != "uncovered" || uncovered.Outcome != "indeterminate" {
		t.Fatalf("unknown Operation was treated as covered: %+v %v", uncovered, err)
	}
	syncer.options.TrustedPins = map[string]struct{}{}
	unavailable, err := syncer.Evaluate(call(50))
	if err != nil || unavailable.Coverage != "unavailable" || unavailable.Outcome != "indeterminate" {
		t.Fatalf("untrusted configuration was evaluated: %+v %v", unavailable, err)
	}
}

func TestLocalEvaluationEndpointRequiresAdapterToken(t *testing.T) {
	guard := decisionRail("00000000-0000-4000-8000-000000000010",
		"00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
			"id": "large", "phase": "tool_call", "when": decisionCondition("gt", 100),
			"outcome": "deny", "reason": "Too large"}})
	handler := EvaluationHandler(decisionSynchronizer(t, []map[string]any{guard}),
		"abcdefghijklmnopqrstuvwxyz012345")
	body, _ := json.Marshal(call(101))
	request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: %d", unauthorized.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	missingKey := httptest.NewRecorder()
	handler.ServeHTTP(missingKey, request)
	if missingKey.Code != http.StatusBadRequest {
		t.Fatalf("missing action key: %d", missingKey.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	request.Header.Set("Idempotency-Key", "invoice-123")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid adapter failed: %d", response.Code)
	}
	var evaluation Evaluation
	if err := json.Unmarshal(response.Body.Bytes(), &evaluation); err != nil ||
		evaluation.Outcome != "deny" || evaluation.Enforced {
		t.Fatalf("bad Observe response: %+v %v", evaluation, err)
	}
	malformed := call(101)
	malformed.Arguments = json.RawMessage(`{"amount":101} {"amount":1}`)
	if _, err := decisionSynchronizer(t, []map[string]any{guard}).Evaluate(malformed); err == nil {
		t.Fatal("malformed action accepted")
	}
}

func TestObserveApprovalAndResultCoverage(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "review", "when": decisionCondition("gt", 100),
			"outcome": "approval_required", "reason": "Review needed"}})
	policy["operationContract"] = map[string]any{"requiredCoverage": []string{"tool_call", "tool_result"}}
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	approval, err := syncer.Evaluate(call(101))
	if err != nil || approval.Outcome != "approval_required" || approval.Enforced {
		t.Fatalf("Observe approval was misrepresented: %+v %v", approval, err)
	}
	result := call(101)
	result.Phase = "tool_result"
	result.Result = json.RawMessage(`{"status":"ok"}`)
	observed, err := syncer.Evaluate(result)
	if err != nil || observed.Outcome != "approval_required" || observed.Coverage != "evaluated" {
		t.Fatalf("result hook was not evaluated: %+v %v", observed, err)
	}
	result.Result = nil
	if _, err := syncer.Evaluate(result); err == nil {
		t.Fatal("result hook accepted no result")
	}
}
