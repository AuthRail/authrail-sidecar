package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// An advisory execution outcome is evidence, never an authorization or permit.
type observedExecutionReceipt struct {
	OperationVersionID     string        `json:"operationVersionId"`
	ActionKey              string        `json:"actionKey"`
	AttemptID              string        `json:"attemptId"`
	Event                  string        `json:"event"`
	InputSHA256            string        `json:"inputSha256"`
	ProviderIdempotencyKey string        `json:"providerIdempotencyKey"`
	ProviderReference      *string       `json:"providerReference"`
	KeySHA256              string        `json:"keySha256"`
	Proof                  IdentityProof `json:"proof"`
}

type queuedExecutionOutcome struct {
	Receipt     observedExecutionReceipt `json:"receipt"`
	Traceparent string                   `json:"traceparent,omitempty"`
}

type retainedExecutionOutcome struct {
	ReceiptID       string `json:"receiptId"`
	ActionID        string `json:"actionId"`
	State           string `json:"state"`
	Replayed        bool   `json:"replayed"`
	RecordingStatus string `json:"recordingStatus"`
}

func (s *Synchronizer) observedReceiptStatement(r observedExecutionReceipt) []byte {
	data, _ := json.Marshal(struct {
		Type                   string  `json:"type"`
		OrganisationID         string  `json:"organisationId"`
		DeploymentID           string  `json:"deploymentId"`
		OperationVersionID     string  `json:"operationVersionId"`
		ActionKey              string  `json:"actionKey"`
		AttemptID              string  `json:"attemptId"`
		Event                  string  `json:"event"`
		InputSHA256            string  `json:"inputSha256"`
		ProviderIdempotencyKey string  `json:"providerIdempotencyKey"`
		ProviderReference      *string `json:"providerReference"`
		KeySHA256              string  `json:"keySha256"`
		IssuedAt               int64   `json:"issuedAt"`
		ExpiresAt              int64   `json:"expiresAt"`
	}{"authrail.execution.receipt.observe.v1", s.options.OrganisationID, s.options.DeploymentID,
		r.OperationVersionID, r.ActionKey, r.AttemptID, r.Event, r.InputSHA256, r.ProviderIdempotencyKey,
		r.ProviderReference, r.KeySHA256, r.Proof.IssuedAt, r.Proof.ExpiresAt})
	return data
}

func validObservedReceipt(r observedExecutionReceipt) bool {
	if !uuidPattern.MatchString(r.OperationVersionID) || !uuidPattern.MatchString(r.AttemptID) ||
		!actionKeyPattern.MatchString(r.ActionKey) || !actionKeyPattern.MatchString(r.ProviderIdempotencyKey) ||
		!guardDigest.MatchString(r.InputSHA256) || !guardDigest.MatchString(r.KeySHA256) ||
		(r.ProviderReference != nil && !actionKeyPattern.MatchString(*r.ProviderReference)) ||
		r.Proof.IssuedAt <= 0 || r.Proof.ExpiresAt <= r.Proof.IssuedAt || r.Proof.ExpiresAt-r.Proof.IssuedAt > 30 {
		return false
	}
	switch r.Event {
	case "succeeded", "failed", "unknown":
	case "reconciled_succeeded", "reconciled_failed":
		if r.ProviderReference == nil {
			return false
		}
	default:
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Proof.Signature)
	return err == nil && len(signature) == ed25519.SignatureSize
}

func (s *Synchronizer) verifyObservedReceipt(r observedExecutionReceipt) bool {
	if !validObservedReceipt(r) || r.Proof.IssuedAt > s.options.Now().Unix()+5 {
		return false
	}
	signature, _ := base64.RawURLEncoding.DecodeString(r.Proof.Signature)
	for _, key := range s.options.ExecutorPublicKeys {
		digest := sha256.Sum256(key)
		if hex.EncodeToString(digest[:]) == r.KeySHA256 && ed25519.Verify(key, s.observedReceiptStatement(r), signature) {
			return true
		}
	}
	return false
}

func outcomeKey(r observedExecutionReceipt) string {
	return r.OperationVersionID + ":" + r.ActionKey + ":" + r.AttemptID + ":" + r.Event
}
func outcomeFingerprint(r observedExecutionReceipt) string {
	r.Proof = IdentityProof{}
	data, _ := json.Marshal(r)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (s *Synchronizer) enqueueExecutionOutcome(entry queuedExecutionOutcome) error {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return err
	}
	for _, existing := range s.observeQueue.Outcomes {
		if outcomeKey(existing.Receipt) == outcomeKey(entry.Receipt) {
			if outcomeFingerprint(existing.Receipt) == outcomeFingerprint(entry.Receipt) {
				return nil
			}
			return errors.New("execution outcome conflicts with queued evidence")
		}
	}
	if len(s.observeQueue.Entries)+len(s.observeQueue.Outcomes) >= maxObserveReports {
		return errors.New("report queue is full")
	}
	next := s.observeQueue
	next.Outcomes = append(append([]queuedExecutionOutcome{}, next.Outcomes...), entry)
	if err := s.saveObserveQueueLocked(next); err != nil {
		return err
	}
	s.observeQueue = next
	return nil
}

func (s *Synchronizer) acknowledgeExecutionOutcome(entry queuedExecutionOutcome) error {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return err
	}
	for index, existing := range s.observeQueue.Outcomes {
		if outcomeKey(existing.Receipt) == outcomeKey(entry.Receipt) && outcomeFingerprint(existing.Receipt) == outcomeFingerprint(entry.Receipt) {
			next := s.observeQueue
			next.Outcomes = append(append([]queuedExecutionOutcome{}, next.Outcomes[:index]...), next.Outcomes[index+1:]...)
			if err := s.saveObserveQueueLocked(next); err != nil {
				return err
			}
			s.observeQueue = next
			return nil
		}
	}
	return nil
}

func (s *Synchronizer) sendExecutionOutcome(ctx context.Context, entry queuedExecutionOutcome) (retainedExecutionOutcome, error) {
	var retained retainedExecutionOutcome
	body, _ := json.Marshal(entry.Receipt)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.options.ControlPlaneURL, "/")+"/runtime/deployment/execution-receipts/observed", bytes.NewReader(body))
	if err != nil {
		return retained, err
	}
	request.Header.Set("Authorization", "Bearer "+s.options.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", outcomeKey(entry.Receipt))
	if entry.Traceparent != "" {
		request.Header.Set("traceparent", entry.Traceparent)
	}
	response, err := s.options.Client.Do(request)
	if err != nil {
		return retained, errors.New("outcome delivery unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return retained, errors.New("outcome not retained")
	}
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&retained) != nil || !uuidPattern.MatchString(retained.ReceiptID) || !uuidPattern.MatchString(retained.ActionID) {
		return retained, errors.New("outcome response invalid")
	}
	retained.RecordingStatus = "retained"
	return retained, nil
}

func (s *Synchronizer) retryExecutionOutcomes(ctx context.Context) error {
	s.observeMu.Lock()
	entries := append([]queuedExecutionOutcome{}, s.observeQueue.Outcomes...)
	s.observeMu.Unlock()
	if len(entries) > 16 {
		entries = entries[:16]
	}
	var failed bool
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := s.sendExecutionOutcome(attempt, entry)
		cancel()
		if err != nil {
			failed = true
			continue
		}
		if s.acknowledgeExecutionOutcome(entry) != nil {
			failed = true
		}
	}
	if failed {
		return errors.New("execution outcomes remain queued")
	}
	return nil
}

// ObservedExecutionReceiptHandler persists signed outcomes without delaying the customer's tool.
func ObservedExecutionReceiptHandler(s *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(supplied), []byte(adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		traceparent, valid := requestTraceparent(r)
		if !valid {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var receipt observedExecutionReceipt
		var trailing any
		if decoder.Decode(&receipt) != nil || decoder.Decode(&trailing) != io.EOF || !validObservedReceipt(receipt) || len(r.Header.Values("Idempotency-Key")) != 1 || r.Header.Get("Idempotency-Key") != outcomeKey(receipt) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !s.verifyObservedReceipt(receipt) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s.options.Token == "" || s.options.ControlPlaneURL == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		entry := queuedExecutionOutcome{Receipt: receipt, Traceparent: traceparent}
		if s.enqueueExecutionOutcome(entry) != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 750*time.Millisecond)
		defer cancel()
		retained, err := s.sendExecutionOutcome(ctx, entry)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"recordingStatus": "queued"})
			return
		}
		_ = s.acknowledgeExecutionOutcome(entry)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(retained)
	})
}
