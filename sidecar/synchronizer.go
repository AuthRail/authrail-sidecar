package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Options struct {
	ControlPlaneURL    string
	Token              string
	OrganisationID     string
	DeploymentID       string
	TrustedPins        map[string]struct{}
	ExecutorPublicKey  ed25519.PublicKey
	ExecutorPublicKeys []ed25519.PublicKey
	StateFile          string
	Client             *http.Client
	Now                func() time.Time
}

type Snapshot struct {
	Sequence           int64      `json:"sequence"`
	ActiveBundleID     *string    `json:"activeBundleId"`
	Mode               string     `json:"mode"`
	BundleValid        bool       `json:"bundleValid"`
	Coverage           string     `json:"coverage"`
	SyncStatus         string     `json:"syncStatus"`
	LastSyncAt         *time.Time `json:"lastSyncAt,omitempty"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	PendingReports     int        `json:"pendingReports"`
	ExecutorKeySHA256  string     `json:"executorKeySha256,omitempty"`
	ExecutorKeySHA256s []string   `json:"executorKeySha256s,omitempty"`
	BlockedReports     int        `json:"blockedReports"`
}

type diskState struct {
	FormatVersion  int            `json:"formatVersion"`
	OrganisationID string         `json:"organisationId"`
	DeploymentID   string         `json:"deploymentId"`
	Floor          int64          `json:"floor"`
	Current        *Configuration `json:"current"`
}

type Synchronizer struct {
	mu                 sync.RWMutex
	options            Options
	endpoint           string
	state              diskState
	status             string
	lastSync           *time.Time
	observeMu          sync.Mutex
	observeQueue       observeQueueState
	observeQueueLoaded bool
}

func NewSynchronizer(options Options) (*Synchronizer, error) {
	if len(options.ExecutorPublicKey) != 0 && len(options.ExecutorPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("executor public key is invalid")
	}
	options.ExecutorPublicKey = append(ed25519.PublicKey(nil), options.ExecutorPublicKey...)
	if len(options.ExecutorPublicKeys) > 2 {
		return nil, errors.New("at most two executor public keys are supported during rotation")
	}
	for i, key := range options.ExecutorPublicKeys {
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("executor public key is invalid")
		}
		options.ExecutorPublicKeys[i] = append(ed25519.PublicKey(nil), key...)
	}
	if len(options.ExecutorPublicKeys) == 2 &&
		string(options.ExecutorPublicKeys[0]) == string(options.ExecutorPublicKeys[1]) {
		return nil, errors.New("executor public keys must be different")
	}
	if len(options.ExecutorPublicKeys) == 0 && len(options.ExecutorPublicKey) != 0 {
		options.ExecutorPublicKeys = []ed25519.PublicKey{options.ExecutorPublicKey}
	}
	if !uuidPattern.MatchString(options.OrganisationID) ||
		!uuidPattern.MatchString(options.DeploymentID) || options.Token == "" ||
		len(options.TrustedPins) == 0 || options.StateFile == "" {
		return nil, errors.New("deployment identity, credential, trusted keys, and state path are required")
	}
	base, err := url.Parse(options.ControlPlaneURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" ||
		base.Fragment != "" || base.Path != "" ||
		(base.Scheme != "https" && !(base.Scheme == "http" && loopbackHost(base.Hostname()))) {
		return nil, errors.New("control plane URL must be HTTPS or loopback HTTP without a path")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 10 * time.Second}
	}
	client := *options.Client
	// A deployment credential must never follow a control-plane redirect.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	options.Client = &client
	if options.Now == nil {
		options.Now = time.Now
	}
	state, err := loadState(options.StateFile, options.OrganisationID, options.DeploymentID)
	if err != nil {
		return nil, err
	}
	s := &Synchronizer{options: options,
		endpoint: base.String() + "/runtime/deployment/configuration", state: state,
		status: "not_synchronized"}
	s.observeMu.Lock()
	err = s.ensureObserveQueueLocked()
	s.observeMu.Unlock()
	if err != nil {
		return nil, err
	}
	if state.Current != nil {
		if _, err := verifyConfiguration(*state.Current,
			options.OrganisationID, options.DeploymentID, options.TrustedPins, options.Now()); err != nil {
			// Preserve the durable floor. An expired cache may recover with a fresh bundle.
			if strings.Contains(err.Error(), "validity window") {
				s.status = "expired"
			} else {
				return nil, fmt.Errorf("cached bundle is untrusted: %w", err)
			}
		}
	}
	return s, nil
}

func (s *Synchronizer) Sync(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.options.Token)
	req.Header.Set("Accept", "application/json")
	res, err := s.options.Client.Do(req)
	if err != nil {
		s.setStatus("unreachable")
		return errors.New("control plane is unreachable")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		s.mu.Lock()
		defer s.mu.Unlock()
		next := s.state
		next.Current = nil
		if err := saveState(s.options.StateFile, next); err != nil {
			s.status = "storage_error"
			return err
		}
		s.state = next
		s.status = "unauthorized"
		return errors.New("deployment credential is unauthorized")
	}
	if res.StatusCode != http.StatusOK {
		s.setStatus("unreachable")
		return fmt.Errorf("control plane returned status %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxConfigurationBytes+1))
	if err != nil {
		s.setStatus("unreachable")
		return errors.New("control plane response could not be read")
	}
	configuration, err := decodeConfiguration(data)
	if err != nil {
		s.setStatus("untrusted")
		return err
	}
	manifest, err := verifyConfiguration(configuration, s.options.OrganisationID,
		s.options.DeploymentID, s.options.TrustedPins, s.options.Now())
	if err != nil {
		s.setStatus("untrusted")
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if configuration.Deployment.Sequence < s.state.Floor {
		s.status = "rollback_rejected"
		return errors.New("configuration sequence moved backwards")
	}
	if configuration.Deployment.Sequence == s.state.Floor {
		if !sameCurrent(s.state.Current, configuration) {
			s.status = "conflict"
			return errors.New("configuration changed without a new sequence")
		}
		if s.state.Current == nil && configuration.Bundle != nil {
			next := s.state
			next.Current = &configuration
			if err := saveState(s.options.StateFile, next); err != nil {
				s.status = "storage_error"
				return err
			}
			s.state = next
		}
	} else {
		if s.state.Current != nil && s.state.Current.Deployment.ActiveBundleID != nil &&
			configuration.Deployment.ActiveBundleID != nil &&
			*s.state.Current.Deployment.ActiveBundleID == *configuration.Deployment.ActiveBundleID {
			s.status = "conflict"
			return errors.New("new sequence reused the active bundle identity")
		}
		next := diskState{FormatVersion: 1,
			OrganisationID: s.options.OrganisationID, DeploymentID: s.options.DeploymentID,
			Floor: configuration.Deployment.Sequence, Current: &configuration}
		if err := saveState(s.options.StateFile, next); err != nil {
			s.status = "storage_error"
			return err
		}
		s.state = next
	}
	now := s.options.Now()
	s.lastSync = &now
	if manifest == nil {
		s.status = "inactive"
	} else {
		s.status = "current"
	}
	return nil
}

func (s *Synchronizer) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Snapshot{Sequence: s.state.Floor, Mode: "observe",
		Coverage: "configuration_only", SyncStatus: s.status,
		LastSyncAt: s.lastSync}
	for _, key := range s.options.ExecutorPublicKeys {
		digest := sha256.Sum256(key)
		result.ExecutorKeySHA256s = append(result.ExecutorKeySHA256s, hex.EncodeToString(digest[:]))
	}
	if len(result.ExecutorKeySHA256s) > 0 {
		result.ExecutorKeySHA256 = result.ExecutorKeySHA256s[0]
	}
	s.observeMu.Lock()
	for _, entry := range s.observeQueue.Entries {
		if entry.BlockedReason == "" {
			result.PendingReports++
		} else {
			result.BlockedReports++
		}
	}
	s.observeMu.Unlock()
	if s.state.Current == nil || s.state.Current.Bundle == nil {
		return result
	}
	result.ActiveBundleID = s.state.Current.Deployment.ActiveBundleID
	manifest, err := verifyConfiguration(*s.state.Current,
		s.options.OrganisationID, s.options.DeploymentID,
		s.options.TrustedPins, s.options.Now())
	if err == nil && manifest != nil {
		result.BundleValid = true
		result.ExpiresAt = &manifest.ExpiresAt
	}
	return result
}

func (s *Synchronizer) setStatus(status string) {
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
}

func sameCurrent(current *Configuration, next Configuration) bool {
	if current == nil {
		// An authorization failure clears the cached bundle but keeps the
		// sequence floor. A valid credential may restore that same sequence.
		return true
	}
	if current.Deployment.ActiveBundleID == nil || next.Deployment.ActiveBundleID == nil {
		return current.Deployment.ActiveBundleID == nil && next.Deployment.ActiveBundleID == nil
	}
	return *current.Deployment.ActiveBundleID == *next.Deployment.ActiveBundleID &&
		current.Bundle != nil && next.Bundle != nil &&
		current.Bundle.Payload == next.Bundle.Payload &&
		current.Bundle.Signature == next.Bundle.Signature &&
		current.Bundle.KeyID == next.Bundle.KeyID
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadState(path, organisationID, deploymentID string) (diskState, error) {
	empty := diskState{FormatVersion: 1, OrganisationID: organisationID,
		DeploymentID: deploymentID}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("sidecar state file is inaccessible or has unsafe permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxConfigurationBytes+4096 {
		return empty, errors.New("sidecar state file cannot be read")
	}
	var state diskState
	if json.Unmarshal(data, &state) != nil || state.FormatVersion != 1 ||
		state.OrganisationID != organisationID || state.DeploymentID != deploymentID ||
		state.Floor < 0 || (state.Current != nil &&
		state.Current.Deployment.Sequence != state.Floor) {
		return empty, errors.New("sidecar state file is invalid")
	}
	return state, nil
}

func saveState(path string, state diskState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("sidecar state directory cannot be created")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("sidecar state directory has unsafe permissions")
	}
	if old, err := os.Lstat(path); err == nil &&
		(!old.Mode().IsRegular() || old.Mode().Perm()&0077 != 0) {
		return errors.New("sidecar state file has unsafe permissions")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("sidecar state file cannot be inspected")
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxConfigurationBytes+4096 {
		return errors.New("sidecar state cannot be encoded")
	}
	file, err := os.CreateTemp(dir, ".authrail-state-*")
	if err != nil {
		return errors.New("sidecar state cannot be written")
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
