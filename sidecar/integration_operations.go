package sidecar

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

type integrationOperation struct {
	VersionID string          `json:"operationVersionId"`
	Contract  json.RawMessage `json:"contract"`
}
type integrationOperations struct {
	FormatVersion  int                    `json:"formatVersion"`
	OrganisationID string                 `json:"organisationId"`
	DeploymentID   string                 `json:"deploymentId"`
	BundleID       string                 `json:"bundleId"`
	Sequence       int64                  `json:"sequence"`
	Mode           string                 `json:"mode"`
	ExpiresAt      time.Time              `json:"expiresAt"`
	Operations     []integrationOperation `json:"operations"`
}

// IntegrationOperationsHandler exposes only contracts in verified selected configuration, never permission or credentials.
func IntegrationOperationsHandler(s *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.RLock()
		current, floor := s.state.Current, s.state.Floor
		s.mu.RUnlock()
		if current == nil || current.Bundle == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		manifest, err := verifyConfiguration(*current, s.options.OrganisationID, s.options.DeploymentID, s.options.TrustedPins, s.options.Now())
		if err != nil || manifest == nil || manifest.Sequence < floor {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		selected := map[string]json.RawMessage{}
		for _, raw := range manifest.Rails {
			var rail struct {
				VersionID string          `json:"operationVersionId"`
				Contract  json.RawMessage `json:"operationContract"`
			}
			if json.Unmarshal(raw, &rail) != nil || !uuidPattern.MatchString(rail.VersionID) || len(rail.Contract) == 0 || len(rail.Contract) > 128*1024 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			var decoded map[string]any
			if json.Unmarshal(rail.Contract, &decoded) != nil || decoded == nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			canonical, err := json.Marshal(decoded)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if prior, exists := selected[rail.VersionID]; exists && !bytes.Equal(prior, canonical) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			selected[rail.VersionID] = canonical
		}
		versions := make([]string, 0, len(selected))
		for id := range selected {
			versions = append(versions, id)
		}
		sort.Strings(versions)
		operations := make([]integrationOperation, 0, len(versions))
		for _, id := range versions {
			operations = append(operations, integrationOperation{id, selected[id]})
		}
		result := integrationOperations{1, manifest.OrganisationID, manifest.DeploymentID, manifest.BundleID, manifest.Sequence, manifest.Mode, manifest.ExpiresAt, operations}
		body, err := json.Marshal(result)
		if err != nil || len(body) > 512*1024 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}
