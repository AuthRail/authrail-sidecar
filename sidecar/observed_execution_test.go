package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A denied advisory decision must not suppress executor evidence, and retry must never run a tool.
func TestObservedOutcomeQueueSurvivesRestartAndAuthenticatesEvidence(t *testing.T) {
	seed := sha256.Sum256([]byte("synthetic-observed-execution-fixture"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	ready := false
	sends := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends++
		if r.URL.Path != "/runtime/deployment/execution-receipts/observed" || r.Header.Get("Authorization") != "Bearer deployment-token" {
			t.Error("incorrect forwarding")
		}
		if !ready {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"receiptId":"00000000-0000-4000-8000-000000000010","actionId":"00000000-0000-4000-8000-000000000011","state":"succeeded","replayed":false}`))
	}))
	defer upstream.Close()
	options := Options{OrganisationID: "00000000-0000-4000-8000-000000000001", DeploymentID: "00000000-0000-4000-8000-000000000002", StateFile: filepath.Join(t.TempDir(), "private", "state"), Token: "deployment-token", ControlPlaneURL: upstream.URL, Client: upstream.Client(), ExecutorPublicKeys: []ed25519.PublicKey{public}, Now: time.Now}
	syncer := &Synchronizer{options: options}
	keyHash := sha256.Sum256(public)
	issuedAt := time.Now().Unix() - 60 // Delayed evidence is historical, not a fresh permission.
	receipt := observedExecutionReceipt{OperationVersionID: "00000000-0000-4000-8000-000000000003", ActionKey: "intent_123", AttemptID: "00000000-0000-4000-8000-000000000004", Event: "succeeded", InputSHA256: strings.Repeat("a", 64), ProviderIdempotencyKey: "effect_key", KeySHA256: hex.EncodeToString(keyHash[:]), Proof: IdentityProof{IssuedAt: issuedAt, ExpiresAt: issuedAt + 30}}
	receipt.Proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, syncer.observedReceiptStatement(receipt)))
	token := strings.Repeat("t", 32)
	invoke := func(value observedExecutionReceipt, authorization string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		r := httptest.NewRequest(http.MethodPost, "/execution/observed-receipts", bytes.NewReader(body))
		r.Header.Set("Authorization", authorization)
		r.Header.Set("Idempotency-Key", outcomeKey(value))
		w := httptest.NewRecorder()
		ObservedExecutionReceiptHandler(syncer, token).ServeHTTP(w, r)
		return w
	}
	if invoke(receipt, "Bearer wrong").Code != http.StatusUnauthorized {
		t.Fatal("wrong adapter authenticated")
	}
	changed := receipt
	changed.Event = "failed"
	if invoke(changed, "Bearer "+token).Code != http.StatusUnauthorized {
		t.Fatal("changed outcome signature accepted")
	}
	if response := invoke(receipt, "Bearer "+token); response.Code != http.StatusAccepted {
		t.Fatalf("unavailable call was not durably queued: %d", response.Code)
	}
	if invoke(receipt, "Bearer "+token).Code != http.StatusAccepted || len(syncer.observeQueue.Outcomes) != 1 {
		t.Fatal("retry duplicated queued evidence")
	}
	restarted := &Synchronizer{options: options}
	ready = true
	if err := restarted.RetryObservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(restarted.observeQueue.Outcomes) != 0 || sends != 3 {
		t.Fatalf("delivery not drained: %d %d", len(restarted.observeQueue.Outcomes), sends)
	}
}
