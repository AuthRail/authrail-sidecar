package sidecar

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A signed interpretation must not transfer to another caller, input, phase or deployment.
func TestContextualFindingBoundaries(t *testing.T) {
	guard := decisionRail("00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
		"id": "sensitive", "phase": "tool_call", "when": map[string]any{"kind": "compare", "left": map[string]any{"root": "contextual", "path": []string{"sensitivity"}}, "comparison": "eq", "right": map[string]any{"kind": "literal", "value": true}}, "outcome": "deny"}})
	content := guard["content"].(map[string]any)
	content["formatVersion"] = 4
	content["contextual"] = map[string]any{"enabled": true, "assessments": []map[string]any{{"id": "sensitivity", "phase": "tool_call", "question": "Does this material disclose a private credential?", "fields": []map[string]any{{"root": "arguments", "path": []string{"text"}}}, "answer": map[string]any{"type": "boolean"}}}}
	policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{"id": "ordinary", "when": decisionCondition("lte", 100), "outcome": "allow"}})
	s := decisionSynchronizerMode(t, []map[string]any{guard, policy}, "enforce")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := s.state.Current.Bundle
	bundle.VerificationKey.Base64 = base64.StdEncoding.EncodeToString(der)
	fingerprint := sha256.Sum256(der)
	bundle.VerificationKey.SHA256 = hex.EncodeToString(fingerprint[:])
	s.options.TrustedPins = map[string]struct{}{bundle.VerificationKey.SHA256: {}}
	payload, _ := base64.RawURLEncoding.DecodeString(bundle.Payload)
	digest := sha256.Sum256(payload)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	bundle.Signature = base64.StdEncoding.EncodeToString(sig)
	request := call(50)
	request.Arguments = json.RawMessage(`{"amount":50,"text":"Synthetic reviewed material"}`)
	input, _ := observeInputBytes(request)
	inputDigest := sha256.Sum256(input)
	attribution, _ := json.Marshal(request.Attribution)
	attributionDigest := sha256.Sum256(attribution)
	material, _ := json.Marshal([]string{"Synthetic reviewed material"})
	materialDigest := sha256.Sum256(material)
	base := contextualValue{Type: "authrail.contextual.finding.v1", OrganisationID: organisationID, DeploymentID: deploymentID, BundleID: bundleID,
		RailVersionID: guard["versionId"].(string), AssessmentID: "sensitivity", OperationVersionID: decisionOperationID, RequestID: request.RequestID,
		Phase: "tool_call", InputSHA256: hex.EncodeToString(inputDigest[:]), AttributionSHA256: hex.EncodeToString(attributionDigest[:]), MaterialSHA256: hex.EncodeToString(materialDigest[:]), Status: "answered", Value: false, IssuedAt: s.options.Now(), ExpiresAt: s.options.Now().Add(time.Minute)}
	signFinding := func(value contextualValue) ContextualFinding {
		data, _ := json.Marshal(value)
		d := sha256.Sum256(data)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
		return ContextualFinding{Payload: base64.RawURLEncoding.EncodeToString(data), KeyID: bundle.KeyID, Algorithm: "ECDSA_SHA_256", Signature: base64.StdEncoding.EncodeToString(sig)}
	}
	cases := []struct {
		name    string
		change  func(*contextualValue)
		outcome string
	}{
		{"bounded false", func(*contextualValue) {}, "allow"},
		{"bounded true", func(v *contextualValue) { v.Value = true }, "deny"},
		{"uncertain", func(v *contextualValue) { v.Status = "uncertain"; v.Value = nil }, "additional_context_required"},
		{"unavailable", func(v *contextualValue) { v.Status = "unavailable"; v.Value = nil }, "additional_context_required"},
		{"another caller", func(v *contextualValue) { v.AttributionSHA256 = hex.EncodeToString(inputDigest[:]) }, "additional_context_required"},
		{"another tenant", func(v *contextualValue) { v.OrganisationID = deploymentID }, "additional_context_required"},
		{"another input", func(v *contextualValue) { v.InputSHA256 = hex.EncodeToString(materialDigest[:]) }, "additional_context_required"},
		{"another phase", func(v *contextualValue) { v.Phase = "tool_result" }, "additional_context_required"},
		{"expired", func(v *contextualValue) { v.ExpiresAt = s.options.Now().Add(-time.Second) }, "additional_context_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := base
			tc.change(&value)
			request.ContextualFindings = []ContextualFinding{signFinding(value)}
			evaluation, err := s.Evaluate(request)
			if err != nil || evaluation.Outcome != tc.outcome {
				t.Fatalf("got %+v: %v", evaluation, err)
			}
		})
	}
	request.ContextualFindings = nil
	evaluation, err := s.Evaluate(request)
	if err != nil || evaluation.Outcome != "additional_context_required" {
		t.Fatalf("missing interpretation passed: %+v %v", evaluation, err)
	}
	request.ContextualFindings = []ContextualFinding{signFinding(base), signFinding(base)}
	evaluation, err = s.Evaluate(request)
	if err != nil || evaluation.Outcome != "additional_context_required" {
		t.Fatalf("duplicate interpretation passed: %+v %v", evaluation, err)
	}
}

func TestResultContextualPlanIncludesRequestDisclosureProcessing(t *testing.T) {
	target := GuardTarget{Root: "arguments", Path: []string{"document"}}
	guard := decisionRail("00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
		"id": "filter", "phase": "tool_call", "when": decisionCondition("lte", 100), "outcome": "allow", "obligations": []GuardObligation{{Kind: "sanitize", HandlerID: "redact", HandlerVersion: strings.Repeat("a", 64), Target: target}},
	}})
	guard["content"].(map[string]any)["formatVersion"] = 4
	guard["operationContract"].(map[string]any)["availableFields"] = []map[string]any{{"root": "arguments", "path": []string{"document"}, "type": "string"}}
	policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", nil)
	policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
	policy["content"].(map[string]any)["contextual"] = map[string]any{"enabled": true, "assessments": []map[string]any{{"id": "review", "phase": "tool_call", "fields": []GuardTarget{target}}}}
	s := decisionSynchronizerMode(t, []map[string]any{guard, policy}, "enforce")
	plan := s.contextualPlan(decisionOperationID, "tool_result")
	if plan.Coverage != "evaluated" || !plan.DisclosureProcessing || len(plan.DisclosureRequirements) != 1 || plan.DisclosureRequirements[0].Target.Root != "arguments" {
		t.Fatalf("request processing omitted before result disclosure: %+v", plan)
	}
}

// The local relay is the last boundary before text leaves the customer's host.
// Even Observe must not send a recognized credential from a protected field.
func TestContextualRelayWithholdsProtectedCredentialMaterial(t *testing.T) {
	credential := "ghp_" + strings.Repeat("a", 36)
	for _, mode := range []string{"observe", "enforce"} {
		for _, protection := range []string{"block", "redact", "invalid_profile"} {
			for _, reuseArguments := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reuse=%v", mode, protection, reuseArguments), func(t *testing.T) {
					target := GuardTarget{Root: "arguments", Path: []string{"text"}}
					rule := map[string]any{"id": "credentials", "phase": "tool_call", "when": credentialCondition("arguments"), "outcome": "deny"}
					if protection == "redact" {
						rule["when"], rule["outcome"] = decisionCondition("lte", 100), "allow"
						rule["obligations"] = []GuardObligation{{Kind: "sanitize", HandlerID: credentialRedactionHandlerID,
							HandlerVersion: credentialRedactionHandlerVersion, Target: target}}
					}
					if protection == "invalid_profile" {
						rule["when"].(map[string]any)["right"] = map[string]any{"kind": "literal", "value": "unknown"}
					}
					guard := decisionRail("00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000011", "guard", []map[string]any{rule})
					guard["content"].(map[string]any)["formatVersion"] = 4
					guard["operationContract"].(map[string]any)["availableFields"] = []availableField{{Root: "arguments", Path: []string{"text"}, Type: "string"}}
					policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", nil)
					policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
					policy["content"].(map[string]any)["contextual"] = map[string]any{"enabled": true,
						"assessments": []map[string]any{{"id": "review", "phase": "tool_call", "fields": []GuardTarget{target}}}}
					s := decisionSynchronizerMode(t, []map[string]any{guard, policy}, mode)
					sent := 0
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						sent++
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(ContextualFinding{Payload: "bounded", KeyID: "key", Algorithm: "ECDSA_SHA_256", Signature: "signed"})
					}))
					defer upstream.Close()
					s.options.ControlPlaneURL, s.options.Client = upstream.URL, upstream.Client()
					phase := "tool_call"
					if reuseArguments {
						phase = "tool_result"
					}
					for _, text := range []string{credential, "[REDACTED]"} {
						request := signedContextualReading(s, policy["versionId"].(string), phase, text)
						data, _ := json.Marshal(request)
						httpRequest := httptest.NewRequest(http.MethodPost, "/contextual-readings", bytes.NewReader(data))
						httpRequest.Header.Set("Authorization", "Bearer adapter-token")
						response := httptest.NewRecorder()
						before := sent
						ContextualHandler(s, "adapter-token").ServeHTTP(response, httpRequest)
						blocked := text == credential || protection == "invalid_profile"
						if blocked && (response.Code != http.StatusBadRequest || sent != before) {
							t.Fatalf("protected text escaped local relay: status=%d sent=%d", response.Code, sent-before)
						}
						if !blocked && (response.Code != http.StatusOK || sent != before+1) {
							t.Fatalf("safe selected material did not reach interpretation: status=%d", response.Code)
						}
					}
				})
			}
		}
	}
}

func signedContextualReading(s *Synchronizer, railID, phase, text string) contextualRequest {
	material, _ := json.Marshal([]string{text})
	materialDigest := sha256.Sum256(material)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyDigest := sha256.Sum256(private.Public().(ed25519.PublicKey))
	request := contextualRequest{FormatVersion: 1, BundleID: bundleID, RailVersionID: railID,
		AssessmentID: "review", OperationVersionID: decisionOperationID, RequestID: decisionRequestID, Phase: phase,
		InputSHA256: strings.Repeat("a", 64), AttributionSHA256: strings.Repeat("b", 64),
		Material: base64.RawURLEncoding.EncodeToString(material), KeySHA256: hex.EncodeToString(keyDigest[:]),
		Proof: IdentityProof{IssuedAt: s.options.Now().Unix(), ExpiresAt: s.options.Now().Add(time.Minute).Unix()}}
	statement := fmt.Sprintf(`{"type":"authrail.contextual.request.v1","organisationId":%q,"deploymentId":%q,"bundleId":%q,"railVersionId":%q,"assessmentId":%q,"operationVersionId":%q,"requestId":%q,"phase":%q,"inputSha256":%q,"attributionSha256":%q,"materialSha256":%q,"keySha256":%q,"issuedAt":%d,"expiresAt":%d}`,
		organisationID, deploymentID, bundleID, railID, request.AssessmentID, decisionOperationID, decisionRequestID, phase,
		request.InputSHA256, request.AttributionSHA256, hex.EncodeToString(materialDigest[:]), request.KeySHA256, request.Proof.IssuedAt, request.Proof.ExpiresAt)
	request.Proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(statement)))
	return request
}
