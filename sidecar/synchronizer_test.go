package sidecar

import (
	"context"
	"crypto/ecdsa"
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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const organisationID = "00000000-0000-4000-8000-000000000001"
const deploymentID = "00000000-0000-4000-8000-000000000002"
const itemID = "00000000-0000-4000-8000-000000000003"
const revisionID = "00000000-0000-4000-8000-000000000004"
const bundleID = "00000000-0000-4000-8000-000000000005"

func testBundle(t *testing.T, sequence int64) (Configuration, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(hash[:])
	id := fmt.Sprintf("00000000-0000-4000-8000-%012x", sequence+4)
	manifest := map[string]any{
		"formatVersion": 1, "bundleId": id,
		"organisationId": organisationID, "deploymentId": deploymentID,
		"inventoryItemId": itemID, "inventoryRevisionId": revisionID,
		"sequence": sequence, "mode": "observe",
		"issuedAt":   "2026-10-16T10:00:00.000Z",
		"activeFrom": "2026-10-16T10:00:00.000Z",
		"expiresAt":  "2026-10-17T10:00:00.000Z",
		"rails":      []any{map[string]any{"railId": "00000000-0000-4000-8000-000000000006"}},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var config Configuration
	config.Deployment.OrganisationID = organisationID
	config.Deployment.DeploymentID = deploymentID
	config.Deployment.InventoryItemID = itemID
	config.Deployment.InventoryRevision = revisionID
	config.Deployment.Mode = "observe"
	config.Deployment.Sequence = sequence
	config.Deployment.ActiveBundleID = pointer(id)
	config.Bundle = &SignedBundle{Payload: base64.RawURLEncoding.EncodeToString(payload),
		KeyID: "key-1", Algorithm: "ECDSA_SHA_256",
		Signature: base64.StdEncoding.EncodeToString(signature)}
	config.Bundle.VerificationKey.Format = "spki-der"
	config.Bundle.VerificationKey.Base64 = base64.StdEncoding.EncodeToString(der)
	config.Bundle.VerificationKey.SHA256 = fingerprint
	return config, fingerprint
}

func pointer(value string) *string { return &value }

func TestAcceptsServerSignedConfiguration(t *testing.T) {
	// Fixture produced by the server's rail-bundle encoder and Node signer.
	data, err := os.ReadFile("testdata/server-configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Pin           string        `json:"pin"`
		Configuration Configuration `json:"configuration"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	manifest, err := verifyConfiguration(fixture.Configuration,
		organisationID, deploymentID, map[string]struct{}{fixture.Pin: {}},
		time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("server-signed configuration was rejected: %v", err)
	}
	if manifest == nil || manifest.BundleID != bundleID ||
		manifest.Sequence != 1 || len(manifest.Rails) != 1 {
		t.Fatalf("server manifest was not read exactly: %+v", manifest)
	}
}

func testOptions(endpoint, file, fingerprint string) Options {
	return Options{ControlPlaneURL: endpoint, Token: "test-credential",
		OrganisationID: organisationID, DeploymentID: deploymentID,
		TrustedPins: map[string]struct{}{fingerprint: {}}, StateFile: file,
		Now: func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }}
}

func TestSyncPersistsSequenceAndRevocation(t *testing.T) {
	active, fingerprint := testBundle(t, 1)
	var mu sync.RWMutex
	current := active
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runtime/deployment/configuration" ||
			r.Header.Get("Authorization") != "Bearer test-credential" {
			t.Error("wrong workload request")
		}
		mu.RLock()
		defer mu.RUnlock()
		_ = json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "private", "state.json")
	syncer, err := NewSynchronizer(testOptions(server.URL, path, fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := syncer.Snapshot(); got.Sequence != 1 || !got.BundleValid ||
		got.Coverage != "configuration_only" {
		t.Fatalf("bad active status: %+v", got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe state file: %v", err)
	}
	mu.Lock()
	current.Deployment.Sequence = 2
	current.Deployment.ActiveBundleID = nil
	current.Bundle = nil
	mu.Unlock()
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := syncer.Snapshot(); got.Sequence != 2 || got.BundleValid ||
		got.ActiveBundleID != nil {
		t.Fatalf("revocation was not applied: %+v", got)
	}
	mu.Lock()
	current = active
	mu.Unlock()
	if err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("old sequence was accepted")
	}
	if got := syncer.Snapshot(); got.Sequence != 2 || got.BundleValid {
		t.Fatalf("old bundle replaced revocation: %+v", got)
	}
	restarted, err := NewSynchronizer(testOptions(server.URL, path, fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Snapshot(); got.Sequence != 2 || got.BundleValid {
		t.Fatalf("restart lost sequence floor: %+v", got)
	}
}

func TestRejectsUnpinnedTamperedAndWrongAudienceBundles(t *testing.T) {
	active, fingerprint := testBundle(t, 1)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if _, err := verifyConfiguration(active, organisationID, deploymentID,
		map[string]struct{}{fingerprint: {}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyConfiguration(active, organisationID, deploymentID,
		map[string]struct{}{"f": {}}, now); err == nil {
		t.Fatal("unknown key accepted")
	}
	changed := active
	copyBundle := *active.Bundle
	changed.Bundle = &copyBundle
	changed.Bundle.Signature = base64.StdEncoding.EncodeToString([]byte("bad"))
	if _, err := verifyConfiguration(changed, organisationID, deploymentID,
		map[string]struct{}{fingerprint: {}}, now); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if _, err := verifyConfiguration(active, organisationID, itemID,
		map[string]struct{}{fingerprint: {}}, now); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := verifyConfiguration(active, organisationID, deploymentID,
		map[string]struct{}{fingerprint: {}}, now.Add(48*time.Hour)); err == nil {
		t.Fatal("expired bundle accepted")
	}
}

func TestCachedBundleSurvivesOutageButNotExpiry(t *testing.T) {
	active, fingerprint := testBundle(t, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(active)
	}))
	path := filepath.Join(t.TempDir(), "private", "state.json")
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	options := testOptions(server.URL, path, fingerprint)
	options.Now = func() time.Time { return now }
	syncer, err := NewSynchronizer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("outage was hidden")
	}
	if got := syncer.Snapshot(); !got.BundleValid || got.SyncStatus != "unreachable" {
		t.Fatalf("valid Observe cache lost during outage: %+v", got)
	}
	now = now.Add(48 * time.Hour)
	if got := syncer.Snapshot(); got.BundleValid {
		t.Fatalf("expired cache usable: %+v", got)
	}
	if _, err := NewSynchronizer(options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSynchronizer(options); err == nil {
		t.Fatal("corrupt floor was reset")
	}
}

func TestConfigurationRequiresExplicitTrustAndLoopbackForHTTP(t *testing.T) {
	if _, err := ParsePins(""); err == nil {
		t.Fatal("missing pin accepted")
	}
	if _, err := ParsePins("ABC"); err == nil {
		t.Fatal("malformed pin accepted")
	}
	active, fingerprint := testBundle(t, 1)
	_ = active
	if _, err := NewSynchronizer(testOptions("http://example.com", filepath.Join(t.TempDir(), "state"),
		fingerprint)); err == nil {
		t.Fatal("remote plaintext HTTP accepted")
	}
}

func TestConfigurationRedirectDoesNotForwardDeploymentCredential(t *testing.T) {
	var targetReached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		targetReached.Store(true)
		if r.Header.Get("Authorization") != "" {
			t.Error("deployment credential reached the redirect target")
		}
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-credential" {
			t.Error("initial request did not authenticate")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	_, fingerprint := testBundle(t, 1)
	syncer, err := NewSynchronizer(testOptions(redirect.URL,
		filepath.Join(t.TempDir(), "private", "state.json"), fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("redirected configuration was accepted")
	}
	if targetReached.Load() {
		t.Fatal("configuration request followed a redirect")
	}
}

func TestOverlappingPinnedKeysAllowSignedRotation(t *testing.T) {
	first, firstPin := testBundle(t, 1)
	second, secondPin := testBundle(t, 2)
	var mu sync.RWMutex
	current := first
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		_ = json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()
	options := testOptions(server.URL, filepath.Join(t.TempDir(), "private", "state.json"), firstPin)
	options.TrustedPins[secondPin] = struct{}{}
	syncer, err := NewSynchronizer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	current = second
	mu.Unlock()
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := syncer.Snapshot(); got.Sequence != 2 || !got.BundleValid {
		t.Fatalf("rotated key was not accepted: %+v", got)
	}
	delete(options.TrustedPins, firstPin)
	if _, err := NewSynchronizer(options); err != nil {
		t.Fatalf("new key could not restart after old pin removal: %v", err)
	}
}

func TestCredentialRecoveryRestoresInactiveSequence(t *testing.T) {
	active, fingerprint := testBundle(t, 1)
	current := active
	unauthorized := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unauthorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()
	options := testOptions(server.URL, filepath.Join(t.TempDir(), "private", "state.json"), fingerprint)
	syncer, err := NewSynchronizer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	unauthorized = true
	if err := syncer.Sync(context.Background()); err == nil {
		t.Fatal("unauthorized credential was accepted")
	}
	if got := syncer.Snapshot(); got.BundleValid || got.Sequence != 1 {
		t.Fatalf("authorization failure retained a usable bundle: %+v", got)
	}
	unauthorized = false
	current.Deployment.ActiveBundleID = nil
	current.Bundle = nil
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("same-sequence inactive configuration did not recover: %v", err)
	}
	if got := syncer.Snapshot(); got.SyncStatus != "inactive" || got.Sequence != 1 {
		t.Fatalf("inactive configuration was not restored: %+v", got)
	}
}
