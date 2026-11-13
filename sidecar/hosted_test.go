package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostedCacheIsolationTrustAndInvalidation(t *testing.T) {
	policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{"id": "ordinary", "when": decisionCondition("lte", 100), "outcome": "allow"}})
	syncer := decisionSynchronizerMode(t, []map[string]any{policy}, "enforce")
	configuration, _ := json.Marshal(syncer.state.Current)
	digest := sha256.Sum256(configuration)
	input := hostedRequest{HostedBinding: HostedBinding{organisationID, deploymentID, bundleID, 1, hex.EncodeToString(digest[:])}, ActionKey: "one",
		Request: signedCall(t, syncer, call(1), "one"), ExecutorPublicKeys: []string{base64.RawURLEncoding.EncodeToString(syncer.options.ExecutorPublicKey)}, TrustedPins: []string{syncer.state.Current.Bundle.VerificationKey.SHA256}}
	hosted := NewHostedEvaluator(nil)
	hosted.now = syncer.options.Now
	invoke := func(path string, value any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		r := httptest.NewRequest("POST", path, bytes.NewReader(body))
		w := httptest.NewRecorder()
		hosted.Handler().ServeHTTP(w, r)
		return w
	}
	if w := invoke("/evaluate", input); w.Code != 409 {
		t.Fatalf("cache miss: %d %s", w.Code, w.Body.String())
	}
	input.Configuration = string(configuration)
	if w := invoke("/evaluate", input); w.Code != 200 || !strings.Contains(w.Body.String(), `"outcome":"allow"`) {
		t.Fatalf("real engine: %d %s", w.Code, w.Body.String())
	}
	input.Configuration = ""
	if w := invoke("/evaluate", input); w.Code != 200 {
		t.Fatalf("cache hit: %d", w.Code)
	}
	rounded := input
	rounded.Request.Arguments = json.RawMessage(`{"amount":0.1}`)
	rounded.Request = signedCall(t, syncer, rounded.Request, rounded.ActionKey)
	raw, _ := json.Marshal(rounded.Request)
	rounded.RequestJSON = strings.Replace(string(raw), `"amount":0.1`, `"amount":0.10000000000000001`, 1)
	if w := invoke("/evaluate", rounded); w.Code == 200 && strings.Contains(w.Body.String(), `"outcome":"allow"`) {
		t.Fatal("raw request number was silently rounded")
	}
	forged := input
	forged.TrustedPins = []string{strings.Repeat("a", 64)}
	if w := invoke("/evaluate", forged); w.Code == 200 && strings.Contains(w.Body.String(), `"outcome":"allow"`) {
		t.Fatal("cached configuration bypassed current signer trust")
	}
	forged = input
	forged.ExecutorPublicKeys = []string{base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	if w := invoke("/evaluate", forged); w.Code != 401 {
		t.Fatalf("cached key authority: %d", w.Code)
	}
	forged = input
	forged.OrganisationID = "00000000-0000-4000-8000-000000000099"
	if w := invoke("/evaluate", forged); w.Code != 409 {
		t.Fatalf("tenant cache isolation: %d", w.Code)
	}
	if w := invoke("/cache/invalidate", []map[string]string{{"organisationId": organisationID, "deploymentId": deploymentID}}); w.Code != 204 {
		t.Fatalf("invalidate: %d", w.Code)
	}
	if w := invoke("/evaluate", input); w.Code != 409 {
		t.Fatalf("invalidation retained entry: %d", w.Code)
	}
	input.Configuration = string(configuration)
	input.ConfigurationSHA256 = strings.Repeat("b", 64)
	if w := invoke("/evaluate", input); w.Code != 400 {
		t.Fatalf("tampered configuration: %d", w.Code)
	}
	input.ConfigurationSHA256 = hex.EncodeToString(digest[:])
	if w := invoke("/evaluate", input); w.Code != 200 {
		t.Fatalf("reload: %d", w.Code)
	}
	input.Configuration = ""
	now := syncer.options.Now()
	hosted.now = func() time.Time { return now.Add(2 * time.Minute) }
	if w := invoke("/evaluate", input); w.Code != 409 {
		t.Fatalf("expired cache entry: %d", w.Code)
	}
}
