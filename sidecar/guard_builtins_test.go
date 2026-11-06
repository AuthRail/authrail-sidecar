package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func credentialCondition(root string) map[string]any {
	return map[string]any{"kind": "compare", "left": map[string]any{"root": root, "path": []string{"text"}},
		"comparison": "matches_credentials_v1", "right": map[string]any{"kind": "literal", "value": "credential_formats_v1"}}
}

// A missing field or unsupported profile cannot turn a credential check into an
// ordinary allow; call and result checks must use the same deterministic detector.
func TestCredentialGuardDecisions(t *testing.T) {
	for _, phase := range []string{"tool_call", "tool_result"} {
		root := "arguments"
		if phase == "tool_result" {
			root = "result"
		}
		guard := decisionRail("00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000011", "guard", []map[string]any{{
			"id": "credentials", "phase": phase, "when": credentialCondition(root), "outcome": "deny"}})
		guard["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
		policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{"id": "ordinary", "when": decisionCondition("lte", 100), "outcome": "allow"}})
		policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
		s := decisionSynchronizerMode(t, []map[string]any{guard, policy}, "enforce")
		for _, sample := range []struct {
			name, text, outcome string
		}{
			{"safe", `"public status"`, "allow"},
			{"github", `"ghp_` + strings.Repeat("a", 36) + `"`, "deny"},
			{"long identifier", `"ghp_` + strings.Repeat("a", 37) + `"`, "allow"},
			{"private key", `"-----BEGIN OPENSSH PRIVATE KEY-----"`, "deny"},
			{"missing", "", "additional_context_required"},
			{"wrong type", "42", "additional_context_required"},
		} {
			t.Run(phase+"/"+sample.name, func(t *testing.T) {
				request := call(50)
				request.Phase = phase
				material := `{"amount":50`
				if sample.text != "" {
					material += `,"text":` + sample.text
				}
				material += "}"
				if phase == "tool_call" {
					request.Arguments = json.RawMessage(material)
				} else {
					request.Result = json.RawMessage(material)
				}
				decision, err := s.Evaluate(request)
				if err != nil || decision.Outcome != sample.outcome {
					t.Fatalf("credential guard returned %+v: %v", decision, err)
				}
			})
		}
	}
	for _, right := range []map[string]any{{"kind": "literal", "value": "another_profile"}, {"kind": "field", "field": map[string]any{"root": "arguments", "path": []string{"profile"}}}} {
		node := credentialCondition("arguments")
		node["right"] = right
		raw, _ := json.Marshal(node)
		if _, _, err := evaluateCondition(raw, map[string]any{"text": "safe", "profile": "credential_formats_v1"}, nil, Attribution{}, nil, nil, 0); err == nil {
			t.Fatal("invalid credential profile was accepted")
		}
	}
}

// A correct digest is not sufficient when the claimed built-in leaves a
// recognized credential in the field, or substitutes another implementation.
func TestBuiltinCredentialEvidenceRequiresCleanOutput(t *testing.T) {
	target := GuardTarget{Root: "arguments", Path: []string{"text"}}
	obligation := GuardObligation{Kind: "sanitize", HandlerID: credentialRedactionHandlerID,
		HandlerVersion: credentialRedactionHandlerVersion, Target: target}
	for _, changed := range []GuardObligation{
		{Kind: "transform", HandlerID: credentialRedactionHandlerID, HandlerVersion: credentialRedactionHandlerVersion, Target: target},
		{Kind: "sanitize", HandlerID: credentialRedactionHandlerID, HandlerVersion: strings.Repeat("a", 64), Target: target},
	} {
		if validGuardObligation(changed, "tool_call") {
			t.Fatal("reserved handler declaration was substituted")
		}
	}
	for _, text := range []string{"[REDACTED]", "ghp_" + strings.Repeat("a", 36)} {
		encoded, _ := json.Marshal(text)
		digest := sha256.Sum256(encoded)
		proof := GuardEvidence{BundleID: bundleID, Phase: "tool_call", Kind: obligation.Kind,
			HandlerID: obligation.HandlerID, HandlerVersion: obligation.HandlerVersion, Target: target,
			InputSHA256: strings.Repeat("b", 64), OutputSHA256: hex.EncodeToString(digest[:])}
		statuses := evaluateGuardObligations([]GuardRequirement{{RailVersionID: decisionOperationID,
			RuleID: "redact", GuardObligation: obligation}}, []GuardEvidence{proof}, "tool_call", bundleID, map[string]any{"text": text}, nil)
		if (statuses[0].Status == "fulfilled") != (text == "[REDACTED]") {
			t.Fatal("unclean redaction proof cleared the Guard")
		}
	}
}
