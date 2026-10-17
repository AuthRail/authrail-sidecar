package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const maxObserveReports = 512
const maxObserveQueueBytes = 16 * 1024 * 1024

type queuedObserve struct {
	ActionKey string          `json:"actionKey"`
	Phase     string          `json:"phase"`
	Body      json.RawMessage `json:"body"`
}

type observeQueueState struct {
	FormatVersion  int             `json:"formatVersion"`
	OrganisationID string          `json:"organisationId"`
	DeploymentID   string          `json:"deploymentId"`
	Entries        []queuedObserve `json:"entries"`
}

func (s *Synchronizer) observeQueuePath() string { return s.options.StateFile + ".observations" }

func (s *Synchronizer) ensureObserveQueueLocked() error {
	if s.observeQueueLoaded {
		return nil
	}
	if s.options.StateFile == "" {
		return errors.New("sidecar state path is required")
	}
	state := observeQueueState{FormatVersion: 1,
		OrganisationID: s.options.OrganisationID, DeploymentID: s.options.DeploymentID,
		Entries: []queuedObserve{}}
	path := s.observeQueuePath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		s.observeQueue = state
		s.observeQueueLoaded = true
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() > maxObserveQueueBytes {
		return errors.New("Observe report queue is inaccessible or unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &state) != nil || state.FormatVersion != 1 ||
		state.OrganisationID != s.options.OrganisationID ||
		state.DeploymentID != s.options.DeploymentID || len(state.Entries) > maxObserveReports {
		return errors.New("Observe report queue is invalid")
	}
	seen := make(map[string]struct{}, len(state.Entries))
	for _, entry := range state.Entries {
		key := entry.ActionKey + "\x00" + entry.Phase
		if !actionKeyPattern.MatchString(entry.ActionKey) ||
			(entry.Phase != "tool_call" && entry.Phase != "tool_result") ||
			validateQueuedObserveBody(entry.Body) != nil {
			return errors.New("Observe report queue contains invalid entries")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("Observe report queue has duplicate entries")
		}
		seen[key] = struct{}{}
	}
	s.observeQueue = state
	s.observeQueueLoaded = true
	return nil
}

func (s *Synchronizer) enqueueObserve(entry queuedObserve) (queuedObserve, error) {
	if err := validateQueuedObserveBody(entry.Body); err != nil {
		return queuedObserve{}, err
	}
	newFingerprint, _ := stableObserveFingerprint(entry.Body)
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return queuedObserve{}, err
	}
	for _, existing := range s.observeQueue.Entries {
		if existing.ActionKey == entry.ActionKey && existing.Phase == entry.Phase {
			existingFingerprint, _ := stableObserveFingerprint(existing.Body)
			if existingFingerprint == newFingerprint {
				return existing, nil
			}
			return queuedObserve{}, errors.New("Observe action key and phase already have different queued input")
		}
	}
	if len(s.observeQueue.Entries) >= maxObserveReports || len(entry.Body) > 32_000 {
		return queuedObserve{}, errors.New("Observe report queue is full")
	}
	next := s.observeQueue
	next.Entries = append(append([]queuedObserve{}, s.observeQueue.Entries...), entry)
	if err := s.saveObserveQueueLocked(next); err != nil {
		return queuedObserve{}, err
	}
	s.observeQueue = next
	return entry, nil
}

func (s *Synchronizer) acknowledgeObserve(entry queuedObserve) error {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return err
	}
	for index, existing := range s.observeQueue.Entries {
		if existing.ActionKey == entry.ActionKey && existing.Phase == entry.Phase &&
			bytes.Equal(existing.Body, entry.Body) {
			next := s.observeQueue
			next.Entries = append(append([]queuedObserve{}, s.observeQueue.Entries[:index]...),
				s.observeQueue.Entries[index+1:]...)
			if err := s.saveObserveQueueLocked(next); err != nil {
				return err
			}
			s.observeQueue = next
			return nil
		}
	}
	return nil
}

func (s *Synchronizer) saveObserveQueueLocked(state observeQueueState) error {
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxObserveQueueBytes {
		return errors.New("Observe report queue is full")
	}
	path := s.observeQueuePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("Observe queue directory cannot be created")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("Observe queue directory has unsafe permissions")
	}
	if old, err := os.Lstat(path); err == nil &&
		(!old.Mode().IsRegular() || old.Mode().Perm()&0077 != 0) {
		return errors.New("Observe queue file has unsafe permissions")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("Observe queue file cannot be inspected")
	}
	file, err := os.CreateTemp(dir, ".authrail-observe-*")
	if err != nil {
		return errors.New("Observe queue cannot be written")
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// RetryObservations replays a bounded batch. The server's action key and phase
// deduplicate a crash after acceptance but before local acknowledgement.
func (s *Synchronizer) RetryObservations(ctx context.Context) error {
	s.observeMu.Lock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		s.observeMu.Unlock()
		return err
	}
	entries := append([]queuedObserve{}, s.observeQueue.Entries...)
	s.observeMu.Unlock()
	if len(entries) > 16 {
		entries = entries[:16]
	}
	var failed bool
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := s.sendObserve(ctx, entry); err != nil {
			failed = true
			continue
		}
		if err := s.acknowledgeObserve(entry); err != nil {
			failed = true
		}
	}
	if failed {
		return errors.New("some Observe reports remain queued")
	}
	return nil
}

// Ensure the queue never contains raw tool payload keys, even if a caller
// accidentally passes a different JSON body in the future.
func validateQueuedObserveBody(body []byte) error {
	if len(body) > 32_000 || !json.Valid(body) {
		return errors.New("Observe report is invalid")
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) != nil ||
		(len(value) != 4 && len(value) != 5 && len(value) != 6) ||
		value["formatVersion"] == nil || value["inputSha256"] == nil ||
		value["attribution"] == nil || value["report"] == nil {
		return errors.New("Observe report is invalid")
	}
	if len(value) >= 5 && value["identityVerification"] == nil {
		return errors.New("Observe report is invalid")
	}
	if len(value) == 6 && value["executorProof"] == nil {
		return errors.New("Observe report is invalid")
	}
	if len(value) >= 5 && bytes.Equal(value["identityVerification"], []byte("null")) {
		return errors.New("Observe report is invalid")
	}
	if len(value) == 6 && bytes.Equal(value["executorProof"], []byte("null")) {
		return errors.New("Observe report is invalid")
	}
	if len(value) >= 5 {
		var identityKeys map[string]json.RawMessage
		if json.Unmarshal(value["identityVerification"], &identityKeys) != nil ||
			len(identityKeys) != 2 || identityKeys["keySha256"] == nil ||
			identityKeys["signatureSha256"] == nil {
			return errors.New("Observe identity verification is invalid")
		}
	}
	_, err := stableObserveFingerprint(body)
	return err
}

func stableObserveFingerprint(body []byte) (string, error) {
	var value struct {
		FormatVersion        int                   `json:"formatVersion"`
		InputSHA256          string                `json:"inputSha256"`
		Attribution          Attribution           `json:"attribution"`
		IdentityVerification *IdentityVerification `json:"identityVerification"`
		ExecutorProof        *IdentityProof        `json:"executorProof"`
		Report               struct {
			OperationVersionID string `json:"operationVersionId"`
			Phase              string `json:"phase"`
		} `json:"report"`
	}
	if json.Unmarshal(body, &value) != nil || value.FormatVersion != 1 ||
		len(value.InputSHA256) != 64 || !uuidPattern.MatchString(value.Report.OperationVersionID) ||
		(value.Report.Phase != "tool_call" && value.Report.Phase != "tool_result") ||
		!identityRefPattern.MatchString(value.Attribution.PrincipalID) ||
		!identityRefPattern.MatchString(value.Attribution.SessionID) ||
		(value.Attribution.ResourceID != nil &&
			!identityRefPattern.MatchString(*value.Attribution.ResourceID)) {
		return "", errors.New("Observe report is invalid")
	}
	if _, err := hex.DecodeString(value.InputSHA256); err != nil {
		return "", errors.New("Observe digest is invalid")
	}
	if value.IdentityVerification != nil {
		if value.ExecutorProof != nil && value.ExecutorProof.Signature == "" {
			return "", errors.New("Observe identity proof is invalid")
		}
		if len(value.IdentityVerification.KeySHA256) != 64 ||
			len(value.IdentityVerification.SignatureSHA256) != 64 {
			return "", errors.New("Observe identity verification is invalid")
		}
		if _, err := hex.DecodeString(value.IdentityVerification.KeySHA256); err != nil {
			return "", errors.New("Observe identity verification is invalid")
		}
		if _, err := hex.DecodeString(value.IdentityVerification.SignatureSHA256); err != nil {
			return "", errors.New("Observe identity verification is invalid")
		}
		if value.ExecutorProof != nil {
			proof := value.ExecutorProof
			signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
			if err != nil || len(signature) != ed25519.SignatureSize ||
				proof.IssuedAt <= 0 || proof.ExpiresAt <= proof.IssuedAt ||
				proof.ExpiresAt-proof.IssuedAt > 60 {
				return "", errors.New("Observe identity proof is invalid")
			}
			digest := sha256.Sum256(signature)
			if value.IdentityVerification.SignatureSHA256 != hex.EncodeToString(digest[:]) {
				return "", errors.New("Observe identity proof digest is invalid")
			}
		}
	}
	identityKeySHA256 := ""
	if value.IdentityVerification != nil {
		identityKeySHA256 = value.IdentityVerification.KeySHA256
	}
	canonical, err := json.Marshal(struct {
		InputSHA256        string      `json:"inputSha256"`
		Attribution        Attribution `json:"attribution"`
		OperationVersionID string      `json:"operationVersionId"`
		Phase              string      `json:"phase"`
		IdentityKeySHA256  string      `json:"identityKeySha256"`
	}{value.InputSHA256, value.Attribution, value.Report.OperationVersionID, value.Report.Phase,
		identityKeySHA256})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
