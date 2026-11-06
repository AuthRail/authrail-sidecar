package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fixed formats must not silently grow into broad personal-data guesses or partial-number matches.
func TestSensitiveFormatBoundaries(t *testing.T) {
	for _, test := range []struct {
		profile, text string
		matches       bool
	}{
		{"email_address_v1", "Contact user.name+tag@example.com.", true},
		{"email_address_v1", "user@example.co.uk", true},
		{"email_address_v1", "user@localhost", false},
		{"email_address_v1", "user..name@example.com", false},
		{"email_address_v1", "user.@example.com", false},
		{"email_address_v1", strings.Repeat("a", 65) + "@example.com", false},
		{"email_address_v1", "user@example.c", false},
		{"email_address_v1", "user@example.123", false},
		{"email_address_v1", "user@example.com-", false},
		{"payment_card_v1", "4111 1111 1111 1111", true},
		{"payment_card_v1", "3782-822463-10005", true},
		{"payment_card_v1", "4111111111111112", false},
		{"payment_card_v1", "0000000000000000", false},
		{"payment_card_v1", "411111111111111112345", false},
		{"payment_card_v1", "４１１１１１１１１１１１１１１１", false},
	} {
		if got := sensitiveFormatV1(test.profile, test.text); got != test.matches {
			t.Errorf("%s format mismatch for %q", test.profile, test.text)
		}
	}
}

func TestSensitiveComparisonRejectsUnavailableOrUnreviewedInputs(t *testing.T) {
	for _, profile := range []string{"email_address_v1", "payment_card_v1"} {
		node := map[string]any{"kind": "compare", "left": map[string]any{"root": "arguments", "path": []string{"text"}}, "comparison": "matches_sensitive_v1", "right": map[string]any{"kind": "literal", "value": profile}}
		encoded, _ := json.Marshal(node)
		for _, args := range []map[string]any{{}, {"text": 42}} {
			matched, unresolved, err := evaluateCondition(encoded, args, nil, Attribution{}, nil, nil, 0)
			if err != nil || matched || len(unresolved) != 1 {
				t.Fatalf("missing/type-invalid input cleared sensitive check: %v %v %v", matched, unresolved, err)
			}
		}
		node["right"] = map[string]any{"kind": "literal", "value": "unreviewed"}
		encoded, _ = json.Marshal(node)
		if _, _, err := evaluateCondition(encoded, map[string]any{"text": "safe"}, nil, Attribution{}, nil, nil, 0); err == nil {
			t.Fatal("unreviewed profile accepted")
		}
	}
}

// A signed digest cannot substitute another built-in version or claim unsanitized output is safe.
func TestSensitiveBuiltinEvidenceRequiresExactOutput(t *testing.T) {
	for _, test := range []struct{ id, version, unsafe, safe string }{
		{emailRedactionHandlerID, emailRedactionHandlerVersion, "user@example.com", "[REDACTED]"},
		{paymentCardRedactionHandlerID, paymentCardRedactionHandlerVersion, "4111 1111 1111 1111", "[REDACTED]"},
		{withholdFieldHandlerID, withholdFieldHandlerVersion, "otherwise public", "[WITHHELD]"},
	} {
		item := GuardObligation{Kind: "sanitize", HandlerID: test.id, HandlerVersion: test.version, Target: GuardTarget{Root: "arguments", Path: []string{"text"}}}
		changed := item
		changed.HandlerVersion = strings.Repeat("a", 64)
		if !validGuardObligation(item, "tool_call") || validGuardObligation(changed, "tool_call") {
			t.Fatal("builtin version check failed")
		}
		for _, text := range []string{test.unsafe, test.safe} {
			encoded, _ := json.Marshal(text)
			digest := sha256.Sum256(encoded)
			proof := GuardEvidence{BundleID: bundleID, HandlerID: test.id, HandlerVersion: test.version, Kind: "sanitize", Target: item.Target, Phase: "tool_call", InputSHA256: strings.Repeat("a", 64), OutputSHA256: hex.EncodeToString(digest[:])}
			statuses := evaluateGuardObligations([]GuardRequirement{{RailVersionID: "rail", RuleID: "rule", GuardObligation: item}}, []GuardEvidence{proof}, "tool_call", bundleID, map[string]any{"text": text}, nil)
			if (statuses[0].Status == "fulfilled") != (text == test.safe) {
				t.Fatalf("unsafe built-in output accepted: %+v", statuses)
			}
		}
	}
}

// The customer's relay must stop selected protected material before any hosted request, including Observe.
func TestContextualRelayWithholdsSensitiveMaterial(t *testing.T) {
	for _, mode := range []string{"observe", "enforce"} {
		for _, test := range []struct{ profile, handler, version, unsafe, safe, nesting string }{
			{"email_address_v1", "", "", "user@example.com", "public text", ""},
			{"payment_card_v1", "", "", "4111111111111111", "public text", ""},
			{"", emailRedactionHandlerID, emailRedactionHandlerVersion, "user@example.com", "[REDACTED]", ""},
			{"", paymentCardRedactionHandlerID, paymentCardRedactionHandlerVersion, "4111111111111111", "[REDACTED]", ""},
			{"", withholdFieldHandlerID, withholdFieldHandlerVersion, "public text", "[WITHHELD]", ""},
			{"email_address_v1", "", "", "user@example.com", "public text", "all"},
			{"payment_card_v1", "", "", "4111111111111111", "public text", "any"},
			{"credential_formats_v1", "", "", "ghp_" + strings.Repeat("a", 36), "public text", "not"},
		} {
			target := GuardTarget{Root: "arguments", Path: []string{"text"}}
			condition := map[string]any{"kind": "compare", "left": target, "comparison": "matches_sensitive_v1", "right": map[string]any{"kind": "literal", "value": test.profile}}
			rule := map[string]any{"id": "sensitive", "phase": "tool_call", "when": condition, "outcome": "deny"}
			if test.profile == "credential_formats_v1" {
				condition["comparison"] = "matches_credentials_v1"
			}
			if test.nesting == "all" || test.nesting == "any" {
				rule["when"] = map[string]any{"kind": test.nesting, "conditions": []any{condition, decisionCondition("gt", 100)}}
			} else if test.nesting == "not" {
				rule["when"] = map[string]any{"kind": "not", "condition": condition}
			}
			if test.handler != "" {
				rule["when"], rule["outcome"] = decisionCondition("lte", 100), "allow"
				rule["obligations"] = []GuardObligation{{Kind: "sanitize", HandlerID: test.handler, HandlerVersion: test.version, Target: target}}
			}
			guard := decisionRail("00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000011", "guard", []map[string]any{rule})
			guard["content"].(map[string]any)["formatVersion"] = 4
			guard["operationContract"].(map[string]any)["availableFields"] = []availableField{{Root: "arguments", Path: []string{"text"}, Type: "string"}}
			policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", nil)
			policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
			policy["content"].(map[string]any)["contextual"] = map[string]any{"enabled": true, "assessments": []map[string]any{{"id": "review", "phase": "tool_call", "fields": []GuardTarget{target}}}}
			s := decisionSynchronizerMode(t, []map[string]any{guard, policy}, mode)
			sent := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent++
				_ = json.NewEncoder(w).Encode(ContextualFinding{Payload: "bounded", KeyID: "key", Algorithm: "ECDSA_SHA_256", Signature: "signed"})
			}))
			s.options.ControlPlaneURL, s.options.Client = upstream.URL, upstream.Client()
			for _, phase := range []string{"tool_call", "tool_result"} {
				for _, text := range []string{test.unsafe, test.safe} {
					request := signedContextualReading(s, policy["versionId"].(string), phase, text)
					data, _ := json.Marshal(request)
					req := httptest.NewRequest(http.MethodPost, "/contextual-readings", bytes.NewReader(data))
					req.Header.Set("Authorization", "Bearer adapter-token")
					response := httptest.NewRecorder()
					before := sent
					ContextualHandler(s, "adapter-token").ServeHTTP(response, req)
					if text == test.unsafe && (response.Code != http.StatusBadRequest || sent != before) {
						t.Fatalf("protected sensitive material escaped relay: %s %s %s", mode, phase, test.handler+test.profile)
					}
					if text == test.safe && (response.Code != http.StatusOK || sent != before+1) {
						t.Fatalf("safe material did not relay: %d", response.Code)
					}
				}
			}
			upstream.Close()
		}
	}
}

// Unknown profiles and oversized trees cannot bypass pre-disclosure traversal.
func TestDisclosureTraversalRejectsUnreviewedOrOversizedConditions(t *testing.T) {
	node := map[string]any{"kind": "compare", "left": GuardTarget{Root: "arguments", Path: []string{"text"}},
		"comparison": "matches_sensitive_v1", "right": map[string]any{"kind": "literal", "value": "unknown"}}
	raw, _ := json.Marshal(map[string]any{"kind": "not", "condition": node})
	count := 0
	if _, err := collectDisclosureProtections(raw, 0, &count); err == nil {
		t.Fatal("nested unknown profile accepted")
	}
	node["right"] = map[string]any{"kind": "literal", "value": "email_address_v1"}
	raw, _ = json.Marshal(node)
	for i := 0; i < 9; i++ {
		raw, _ = json.Marshal(map[string]any{"kind": "not", "condition": raw})
	}
	count = 0
	if _, err := collectDisclosureProtections(raw, 0, &count); err == nil {
		t.Fatal("overdeep disclosure tree accepted")
	}
	leaf, _ := json.Marshal(node)
	branch := map[string]any{"kind": "all", "conditions": []json.RawMessage{leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf}}
	branchRaw, _ := json.Marshal(branch)
	raw, _ = json.Marshal(map[string]any{"kind": "any", "conditions": []json.RawMessage{branchRaw, branchRaw, branchRaw, branchRaw, branchRaw, branchRaw, branchRaw, branchRaw}})
	count = 0
	if _, err := collectDisclosureProtections(raw, 0, &count); err == nil {
		t.Fatal("oversized disclosure tree accepted")
	}
}
