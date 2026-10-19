package sidecar

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const gapDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func blockedGapFixture(t *testing.T) *Synchronizer {
	t.Helper()
	syncer := decisionSynchronizer(t, nil)
	entry := queuedObserve{ActionKey: "closed-key", Phase: "tool_call",
		Body: json.RawMessage(`{"formatVersion":1,"inputSha256":"` + gapDigest + `","attribution":{"principalId":"staff_123","sessionId":"task_123","resourceId":null},"report":{"operationVersionId":"00000000-0000-4000-8000-000000000008","phase":"tool_call","evaluation":{"requestId":"old"}}}`)}
	if _, err := syncer.enqueueObserve(entry); err != nil {
		t.Fatal(err)
	}
	if err := syncer.blockObserve(entry); err != nil {
		t.Fatal(err)
	}
	return syncer
}

func TestOperatorReviewsAndAcknowledgesLocalGap(t *testing.T) {
	syncer := blockedGapFixture(t)
	token := strings.Repeat("o", 32)
	handler := OperatorGapHandler(syncer, token)
	request := httptest.NewRequest(http.MethodGet, "/observations/gaps", nil)
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatal("gap review was not protected")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, request)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(gapDigest)) ||
		bytes.Contains(listed.Body.Bytes(), []byte("principalId")) {
		t.Fatalf("gap list exposed payload or omitted metadata: %d %s", listed.Code, listed.Body.String())
	}
	input := AcknowledgeGapInput{ActionKey: "closed-key", Phase: "tool_call",
		InputSHA256: gapDigest, Reason: "Reviewed the missing report against application logs"}
	body, _ := json.Marshal(input)
	post := httptest.NewRequest(http.MethodPost, "/observations/gaps/acknowledgements",
		bytes.NewReader(body))
	post.Header.Set("Authorization", "Bearer "+token)
	post.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusOK || syncer.Snapshot().BlockedReports != 0 {
		t.Fatalf("acknowledgement did not free the blocked queue: %d", response.Code)
	}
	ledger, err := os.ReadFile(syncer.gapLedgerPath())
	if err != nil || !bytes.Contains(ledger, []byte(input.Reason)) ||
		bytes.Contains(ledger, []byte("principalId")) {
		t.Fatal("metadata-only review was not retained privately")
	}
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, httptest.NewRequest(http.MethodPost,
		"/observations/gaps/acknowledgements", bytes.NewReader(body)).WithContext(post.Context()))
	if retry.Code != http.StatusUnauthorized {
		t.Fatal("retry without operator token was accepted")
	}
	retried := httptest.NewRequest(http.MethodPost, "/observations/gaps/acknowledgements", bytes.NewReader(body))
	retried.Header.Set("Authorization", "Bearer "+token)
	retried.Header.Set("Content-Type", "application/json")
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, retried)
	if replay.Code != http.StatusOK {
		t.Fatal("idempotent acknowledgement failed")
	}
	history := httptest.NewRequest(http.MethodGet, "/observations/gaps/history", nil)
	history.Header.Set("Authorization", "Bearer "+token)
	seen := httptest.NewRecorder()
	handler.ServeHTTP(seen, history)
	if seen.Code != http.StatusOK || !bytes.Contains(seen.Body.Bytes(), []byte(input.Reason)) {
		t.Fatal("acknowledgement history was not reviewable")
	}
}

func TestGapLedgerSurvivesCrashBeforeQueueRemoval(t *testing.T) {
	syncer := blockedGapFixture(t)
	ledger, err := syncer.loadGapLedgerLocked()
	if err != nil {
		t.Fatal(err)
	}
	ledger.Acknowledgments = append(ledger.Acknowledgments, GapAcknowledgement{
		ObservationGap: ObservationGap{ActionKey: "closed-key", Phase: "tool_call",
			InputSHA256: gapDigest, Reason: "application_key_closed"},
		ReviewReason: "Reviewed against application logs", AcknowledgedAt: time.Now().UTC(),
	})
	if err := syncer.saveGapLedgerLocked(ledger); err != nil {
		t.Fatal(err)
	}
	options := syncer.options
	options.ControlPlaneURL = "http://127.0.0.1:7078"
	options.Token = "deployment-secret"
	restarted, err := NewSynchronizer(options)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Snapshot().BlockedReports != 0 || len(restarted.observeQueue.Entries) != 0 {
		t.Fatal("startup did not finish an acknowledged queue removal")
	}
}

func TestGapAcknowledgementKeepsQueueWhenHistoryUnsafe(t *testing.T) {
	syncer := blockedGapFixture(t)
	if err := os.Symlink(syncer.observeQueuePath(), syncer.gapLedgerPath()); err != nil {
		t.Fatal(err)
	}
	_, err := syncer.AcknowledgeObservationGap(AcknowledgeGapInput{
		ActionKey: "closed-key", Phase: "tool_call", InputSHA256: gapDigest,
		Reason: "Reviewed against application logs"})
	if err == nil || syncer.Snapshot().BlockedReports != 1 {
		t.Fatal("unsafe history path removed a blocked report")
	}
}
