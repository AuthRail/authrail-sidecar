package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/propagation"
)

// ReportSignal sends bounded sidecar state; it does not report tool coverage.
func (s *Synchronizer) ReportSignal(ctx context.Context) error {
	snapshot := s.Snapshot()
	lastSyncAt := snapshot.LastSyncAt
	if lastSyncAt != nil {
		utc := lastSyncAt.UTC()
		lastSyncAt = &utc
	}
	body, err := json.Marshal(struct {
		FormatVersion  int        `json:"formatVersion"`
		Sequence       int64      `json:"sequence"`
		ActiveBundleID *string    `json:"activeBundleId"`
		BundleValid    bool       `json:"bundleValid"`
		SyncStatus     string     `json:"syncStatus"`
		LastSyncAt     *time.Time `json:"lastSyncAt"`
		PendingReports int        `json:"pendingReports"`
		BlockedReports int        `json:"blockedReports"`
	}{1, snapshot.Sequence, snapshot.ActiveBundleID, snapshot.BundleValid,
		snapshot.SyncStatus, lastSyncAt, snapshot.PendingReports, snapshot.BlockedReports})
	if err != nil {
		return errors.New("sidecar signal is invalid")
	}
	signalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(signalCtx, http.MethodPost,
		strings.TrimRight(s.options.ControlPlaneURL, "/")+"/runtime/deployment/signal", bytes.NewReader(body))
	if err != nil {
		return errors.New("sidecar signal could not be prepared")
	}
	request.Header.Set("Authorization", "Bearer "+s.options.Token)
	request.Header.Set("Content-Type", "application/json")
	propagation.TraceContext{}.Inject(signalCtx, propagation.HeaderCarrier(request.Header))
	response, err := s.options.Client.Do(request)
	if err != nil {
		return errors.New("sidecar signal could not be delivered")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return errors.New("sidecar signal was not accepted")
	}
	return nil
}
