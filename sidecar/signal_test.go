package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportSignalIsBoundedAndAuthenticated(t *testing.T) {
	var received struct {
		FormatVersion  int     `json:"formatVersion"`
		Sequence       int64   `json:"sequence"`
		ActiveBundleID *string `json:"activeBundleId"`
		SyncStatus     string  `json:"syncStatus"`
		LastSyncAt     *string `json:"lastSyncAt"`
		PendingReports int     `json:"pendingReports"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/runtime/deployment/signal" || request.Method != http.MethodPost ||
			request.Header.Get("Authorization") != "Bearer deployment-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	syncer := &Synchronizer{options: Options{ControlPlaneURL: server.URL,
		Token: "deployment-token", Client: server.Client()},
		state: diskState{Floor: 2}, status: "unreachable"}
	if err := syncer.ReportSignal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.FormatVersion != 1 || received.Sequence != 2 ||
		received.ActiveBundleID != nil || received.SyncStatus != "unreachable" ||
		received.LastSyncAt != nil || received.PendingReports != 0 {
		t.Fatalf("unexpected sidecar signal: %+v", received)
	}
}
