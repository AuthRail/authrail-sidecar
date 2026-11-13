package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const hostedCacheEntries = 128
const hostedCacheBytes = 32 << 20
const hostedCacheTTL = time.Minute

// HostedBinding identifies immutable configuration, never caller or execution authority.
type HostedBinding struct {
	OrganisationID      string `json:"organisationId"`
	DeploymentID        string `json:"deploymentId"`
	BundleID            string `json:"bundleId"`
	Sequence            int64  `json:"sequence"`
	ConfigurationSHA256 string `json:"configurationSha256"`
}
type hostedRequest struct {
	HostedBinding
	ActionKey          string            `json:"actionKey"`
	Request            EvaluationRequest `json:"request"`
	RequestJSON        string            `json:"requestJSON,omitempty"`
	Configuration      string            `json:"configuration,omitempty"`
	ExecutorPublicKeys []string          `json:"executorPublicKeys"`
	TrustedPins        []string          `json:"trustedPins"`
}
type hostedEntry struct {
	binding       HostedBinding
	configuration Configuration
	bytes         int
	expires       time.Time
	used          uint64
}

// HostedEvaluator owns a bounded, replaceable cache only. The API owns all durable state.
// Mount this handler only on a private Unix socket: its configuration/pins are trusted API input.
type HostedEvaluator struct {
	mu        sync.Mutex
	entries   map[HostedBinding]hostedEntry
	bytes     int
	clock     uint64
	now       func() time.Time
	telemetry *Telemetry
}

func NewHostedEvaluator(telemetry *Telemetry) *HostedEvaluator {
	return &HostedEvaluator{entries: make(map[HostedBinding]hostedEntry), now: time.Now, telemetry: telemetry}
}
func decodeHosted(r *http.Request, limit int64, target any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing body")
	}
	return nil
}
func (h *HostedEvaluator) pruneLocked(now time.Time) {
	for key, entry := range h.entries {
		if !entry.expires.After(now) {
			delete(h.entries, key)
			h.bytes -= entry.bytes
		}
	}
}
func (h *HostedEvaluator) configuration(request hostedRequest) (Configuration, error) {
	binding := request.HostedBinding
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	if entry, ok := h.entries[binding]; ok {
		h.clock++
		entry.used = h.clock
		h.entries[binding] = entry
		return entry.configuration, nil
	}
	if request.Configuration == "" {
		return Configuration{}, errHostedMiss
	}
	sum := sha256.Sum256([]byte(request.Configuration))
	if hex.EncodeToString(sum[:]) != binding.ConfigurationSHA256 {
		return Configuration{}, errors.New("configuration digest mismatch")
	}
	configuration, err := decodeConfiguration([]byte(request.Configuration))
	if err != nil {
		return Configuration{}, err
	}
	pins := make(map[string]struct{})
	for _, pin := range request.TrustedPins {
		pins[pin] = struct{}{}
	}
	manifest, err := verifyConfiguration(configuration, binding.OrganisationID, binding.DeploymentID, pins, now)
	if err != nil || manifest == nil || manifest.BundleID != binding.BundleID || manifest.Sequence != binding.Sequence {
		return Configuration{}, errors.New("configuration binding mismatch")
	}
	// One organisation cannot occupy the whole shared rule cache.
	count := 0
	var oldestTenant HostedBinding
	var tenantUse uint64 = ^uint64(0)
	for key, entry := range h.entries {
		if key.OrganisationID == binding.OrganisationID {
			count++
			if entry.used < tenantUse {
				oldestTenant = key
				tenantUse = entry.used
			}
		}
	}
	if count >= 32 {
		old := h.entries[oldestTenant]
		delete(h.entries, oldestTenant)
		h.bytes -= old.bytes
	}
	for len(h.entries) >= hostedCacheEntries || h.bytes+len(request.Configuration) > hostedCacheBytes {
		var oldest HostedBinding
		var used uint64 = ^uint64(0)
		for key, entry := range h.entries {
			if entry.used < used {
				oldest = key
				used = entry.used
			}
		}
		old := h.entries[oldest]
		delete(h.entries, oldest)
		h.bytes -= old.bytes
	}
	h.clock++
	expires := now.Add(hostedCacheTTL)
	if manifest.ExpiresAt.Before(expires) {
		expires = manifest.ExpiresAt
	}
	h.entries[binding] = hostedEntry{binding, configuration, len(request.Configuration), expires, h.clock}
	h.bytes += len(request.Configuration)
	return configuration, nil
}

var errHostedMiss = errors.New("configuration required")

func (h *HostedEvaluator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /cache/bindings", h.bindings)
	mux.HandleFunc("POST /cache/invalidate", h.invalidate)
	mux.HandleFunc("POST /evaluate", h.evaluate)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}
func (h *HostedEvaluator) bindings(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.pruneLocked(h.now())
	bindings := make([]HostedBinding, 0, len(h.entries))
	for key := range h.entries {
		bindings = append(bindings, key)
	}
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bindings)
}
func (h *HostedEvaluator) invalidate(w http.ResponseWriter, r *http.Request) {
	var scopes []struct {
		OrganisationID string `json:"organisationId"`
		DeploymentID   string `json:"deploymentId"`
	}
	if decodeHosted(r, 64*1024, &scopes) != nil || len(scopes) > hostedCacheEntries {
		w.WriteHeader(400)
		return
	}
	for _, scope := range scopes {
		if !uuidPattern.MatchString(scope.OrganisationID) || !uuidPattern.MatchString(scope.DeploymentID) {
			w.WriteHeader(400)
			return
		}
	}
	h.mu.Lock()
	for key, entry := range h.entries {
		for _, scope := range scopes {
			if key.OrganisationID == scope.OrganisationID && key.DeploymentID == scope.DeploymentID {
				delete(h.entries, key)
				h.bytes -= entry.bytes
				break
			}
		}
	}
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
func (h *HostedEvaluator) evaluate(w http.ResponseWriter, r *http.Request) {
	var request hostedRequest
	if decodeHosted(r, 4<<20, &request) != nil || !uuidPattern.MatchString(request.OrganisationID) || !uuidPattern.MatchString(request.DeploymentID) || !uuidPattern.MatchString(request.BundleID) || request.Sequence < 1 || len(request.ConfigurationSHA256) != 64 || !actionKeyPattern.MatchString(request.ActionKey) || len(request.ExecutorPublicKeys) < 1 || len(request.ExecutorPublicKeys) > 2 || len(request.TrustedPins) < 1 || len(request.TrustedPins) > 2 {
		w.WriteHeader(400)
		return
	}
	// The API preserves raw JSON so a JS parser cannot silently round a signed number.
	if request.RequestJSON != "" {
		if len(request.RequestJSON) > maxEvaluationRequestBytes {
			w.WriteHeader(400)
			return
		}
		decoder := json.NewDecoder(strings.NewReader(request.RequestJSON))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		var original EvaluationRequest
		if decoder.Decode(&original) != nil || decoder.Decode(new(any)) != io.EOF {
			w.WriteHeader(400)
			return
		}
		request.Request = original
	}
	encoded, err := json.Marshal(request.Request)
	if err != nil || len(encoded) > maxEvaluationRequestBytes {
		w.WriteHeader(400)
		return
	}
	configuration, err := h.configuration(request)
	if errors.Is(err, errHostedMiss) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"code":"CONFIGURATION_REQUIRED"}`))
		return
	}
	if err != nil {
		w.WriteHeader(400)
		return
	}
	keys := make([]ed25519.PublicKey, 0, len(request.ExecutorPublicKeys))
	for _, raw := range request.ExecutorPublicKeys {
		key, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		if err != nil || len(key) != ed25519.PublicKeySize {
			w.WriteHeader(400)
			return
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	pins := make(map[string]struct{})
	for _, pin := range request.TrustedPins {
		pins[pin] = struct{}{}
	}
	// Trust metadata is current per request, not cached with the rule selection.
	view := &Synchronizer{options: Options{OrganisationID: request.OrganisationID, DeploymentID: request.DeploymentID, TrustedPins: pins, ExecutorPublicKeys: keys, Now: h.now}, state: diskState{Floor: request.Sequence, Current: &configuration}}
	if view.verifyIdentityProof(request.Request, request.ActionKey) != nil {
		w.WriteHeader(401)
		return
	}
	// Never manufacture complete history from caller input or process memory.
	// Rules requiring verified trajectory remain unavailable until the API supplies durable history.
	if request.Request.Trajectory != nil {
		request.Request.Trajectory.verified = false
	}
	evaluation, err := view.Evaluate(request.Request)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if evaluation.Coverage != "evaluated" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			HostedBinding
			RequestID  string     `json:"requestId"`
			ActionKey  string     `json:"actionKey"`
			Evaluation Evaluation `json:"evaluation"`
			Report     any        `json:"report"`
		}{request.HostedBinding, request.Request.RequestID, request.ActionKey, evaluation, nil})
		return
	}
	report, err := view.observeIntake(request.ActionKey, request.Request, evaluation)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if h.telemetry != nil {
		h.telemetry.RecordDecision(r.Context(), evaluation, request.Request.Phase)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		HostedBinding
		RequestID  string          `json:"requestId"`
		ActionKey  string          `json:"actionKey"`
		Evaluation Evaluation      `json:"evaluation"`
		Report     json.RawMessage `json:"report"`
	}{request.HostedBinding, request.Request.RequestID, request.ActionKey, evaluation, report})
}
