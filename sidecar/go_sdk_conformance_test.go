package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSignedGoSDKVectorAtRealSidecarHandler(t *testing.T) {
	data, err := os.ReadFile("../conformance/v1/signed-go-evaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ExecutorSeedHex string            `json:"executorSeedHex"`
		ActionKey       string            `json:"actionKey"`
		Request         EvaluationRequest `json:"request"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(fixture.ExecutorSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	policy := decisionRail("00000000-0000-4000-8000-000000000012",
		"00000000-0000-4000-8000-000000000013", "policy", []map[string]any{{
			"id": "ordinary", "when": decisionCondition("lte", 100), "outcome": "allow"}})
	syncer := decisionSynchronizer(t, []map[string]any{policy})
	syncer.options.ExecutorPublicKeys = []ed25519.PublicKey{private.Public().(ed25519.PublicKey)}
	if err := syncer.verifyIdentityProof(fixture.Request, fixture.ActionKey); err != nil {
		t.Fatalf("Go SDK proof was rejected by sidecar: %v", err)
	}
	token := strings.Repeat("c", 32)
	request := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(dataRequest(t, fixture.Request)))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", fixture.ActionKey)
	response := httptest.NewRecorder()
	EvaluationHandler(syncer, token).ServeHTTP(response, request)
	var decision Evaluation
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decision) != nil ||
		decision.Outcome != "allow" || decision.Coverage != "evaluated" {
		t.Fatalf("Go wire request did not evaluate: %d %+v", response.Code, decision)
	}
	changed := fixture.Request
	changed.Arguments = json.RawMessage(`{"amount":400}`)
	if err := syncer.verifyIdentityProof(changed, fixture.ActionKey); err == nil {
		t.Fatal("changed business arguments reused the Go proof")
	}
	if err := syncer.verifyIdentityProof(fixture.Request, "other-action"); err == nil {
		t.Fatal("changed business key reused the Go proof")
	}
}

func dataRequest(t *testing.T, request EvaluationRequest) []byte {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The same canonical bytes must be signed by either SDK and verified by the sidecar.
func TestSharedCanonicalInputCorpus(t *testing.T) {
	data, err := os.ReadFile("../conformance/v1/canonical-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name            string              `json:"name"`
			Phase           string              `json:"phase"`
			Arguments       json.RawMessage     `json:"arguments"`
			Result          json.RawMessage     `json:"result"`
			FactResolutions []FactResolution    `json:"factResolutions"`
			Trajectory      *TrajectorySnapshot `json:"trajectory"`
			GuardEvidence   []GuardEvidence     `json:"guardEvidence"`
			CanonicalInput  string              `json:"canonicalInput"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus.Cases {
		t.Run(item.Name, func(t *testing.T) {
			actual, err := observeInputBytes(EvaluationRequest{Phase: item.Phase, Arguments: item.Arguments,
				Result: item.Result, FactResolutions: item.FactResolutions, Trajectory: item.Trajectory, GuardEvidence: item.GuardEvidence})
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != item.CanonicalInput {
				t.Fatalf("canonical mismatch: %s", actual)
			}
		})
	}
}

func TestGuardDeclarationsRejectUnknownSemantics(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"sanitize","handlerId":"redact","handlerVersion":"a","target":{"root":"arguments","path":["text"]},"optional":true}`,
		`{"kind":"sanitize","handlerId":"redact","handlerVersion":"a","target":{"root":"arguments","path":["text"],"wholeObject":true}}`,
	} {
		var item GuardObligation
		if json.Unmarshal([]byte(raw), &item) == nil {
			t.Fatal("unknown Guard semantics accepted")
		}
	}
}
