package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func executionGapFixture(t *testing.T) (*Synchronizer, queuedExecutionOutcome) {
	t.Helper()
	s := decisionSynchronizer(t, nil)
	seed := sha256.Sum256([]byte("execution-gap-test-key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	issued := time.Now().Unix() - 120
	receipt := observedExecutionReceipt{OperationVersionID: "00000000-0000-4000-8000-000000000003", ActionKey: "orphan_intent", AttemptID: "00000000-0000-4000-8000-000000000004", Event: "failed", InputSHA256: strings.Repeat("a", 64), ProviderIdempotencyKey: "orphan_effect", KeySHA256: hex.EncodeToString(digest[:]), Proof: IdentityProof{IssuedAt: issued, ExpiresAt: issued + 30}}
	receipt.Proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, s.observedReceiptStatement(receipt)))
	entry := queuedExecutionOutcome{Receipt: receipt}
	if err := s.enqueueExecutionOutcome(entry); err != nil {
		t.Fatal(err)
	}
	return s, entry
}

func TestExecutionGapWrongFingerprintDoesNotMutateEvidence(t *testing.T) {
	s, _ := executionGapFixture(t)
	before, err := os.ReadFile(s.observeQueuePath())
	if err != nil {
		t.Fatal(err)
	}
	review, err := OpenExecutionGapReview(s.options.StateFile, s.options.OrganisationID, s.options.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := review.Acknowledge(strings.Repeat("b", 64), "operator", "Confirmed unmatched historical report"); err == nil {
		t.Fatal("wrong fingerprint acknowledged")
	}
	after, _ := os.ReadFile(s.observeQueuePath())
	if !bytes.Equal(before, after) {
		t.Fatal("wrong fingerprint changed queue")
	}
	if _, err := os.Stat(s.executionGapArchivePath()); !os.IsNotExist(err) {
		t.Fatal("wrong fingerprint created archive")
	}
}

func TestExecutionGapArchivesExactSignedReceiptAndReplays(t *testing.T) {
	s, entry := executionGapFixture(t)
	review, err := OpenExecutionGapReview(s.options.StateFile, s.options.OrganisationID, s.options.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	pending, history, err := review.List()
	if err != nil || len(pending) != 1 || len(history) != 0 {
		t.Fatal("pending report was not reviewable")
	}
	listed, _ := json.Marshal(pending)
	if bytes.Contains(listed, []byte(entry.Receipt.Proof.Signature)) || bytes.Contains(listed, []byte("providerReference")) {
		t.Fatal("list exposed raw receipt")
	}
	reason := "Reviewed original SDK rejection; no matching call was recorded"
	ack, err := review.Acknowledge(pending[0].Fingerprint, "operator", reason)
	if err != nil {
		t.Fatal(err)
	}
	if ack.RecordingStatus != "acknowledged_gap" {
		t.Fatal("acknowledgement claimed central retention")
	}
	data, err := os.ReadFile(s.executionGapArchivePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(entry.Receipt.Proof.Signature)) || !bytes.Contains(data, []byte(reason)) {
		t.Fatal("signed receipt and review were not archived")
	}
	if review.synchronizer.Snapshot().PendingReports != 0 {
		t.Fatal("reviewed report remained active")
	}
	replay, err := review.Acknowledge(pending[0].Fingerprint, "operator", reason)
	if err != nil || replay != ack {
		t.Fatal("exact replay was not idempotent")
	}
	if _, err := review.Acknowledge(pending[0].Fingerprint, "different_operator", reason); err == nil {
		t.Fatal("changed reviewer overwrote acknowledgement")
	}
	info, _ := os.Stat(s.executionGapArchivePath())
	if info.Mode().Perm() != 0600 {
		t.Fatal("archive is not private")
	}
}

func TestExecutionGapArchiveFailureKeepsQueue(t *testing.T) {
	s, entry := executionGapFixture(t)
	before, _ := os.ReadFile(s.observeQueuePath())
	if err := os.Symlink(s.observeQueuePath(), s.executionGapArchivePath()); err != nil {
		t.Fatal(err)
	}
	review := &ExecutionGapReview{synchronizer: s}
	if _, err := review.Acknowledge(s.executionGap(entry).Fingerprint, "operator", "Reviewed unavailable report with application records"); err == nil {
		t.Fatal("unsafe archive accepted")
	}
	after, _ := os.ReadFile(s.observeQueuePath())
	if !bytes.Equal(before, after) || s.Snapshot().PendingReports != 1 {
		t.Fatal("archive failure removed queued evidence")
	}
}

func TestExecutionGapArchiveBeforeQueueCrashRecoversOnLoad(t *testing.T) {
	s, entry := executionGapFixture(t)
	archive, err := s.loadExecutionGapArchiveLocked()
	if err != nil {
		t.Fatal(err)
	}
	archive.Acknowledgements = append(archive.Acknowledgements, archivedExecutionGap{ExecutionGapAcknowledgement: ExecutionGapAcknowledgement{ExecutionGap: s.executionGap(entry), Reviewer: "operator", ReviewReason: "Reviewed unavailable report with application records", AcknowledgedAt: time.Now().UTC(), RecordingStatus: "acknowledged_gap"}, Report: entry})
	if err := s.saveExecutionGapArchiveLocked(archive); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash before the queued report was removed; a fresh loader
	// must finish that exact durable acknowledgement without network delivery.
	review, err := OpenExecutionGapReview(s.options.StateFile, s.options.OrganisationID, s.options.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	pending, acknowledged, err := review.List()
	if err != nil || len(pending) != 0 || len(acknowledged) != 1 {
		t.Fatal("archive-before-queue recovery failed")
	}
	if review.synchronizer.Snapshot().PendingReports != 0 {
		t.Fatal("recovered acknowledgement still counted as pending")
	}
}

func TestExecutionGapChangedArchiveFailsClosed(t *testing.T) {
	s, entry := executionGapFixture(t)
	archive, _ := s.loadExecutionGapArchiveLocked()
	altered := entry
	altered.Receipt.Proof.IssuedAt--
	archive.Acknowledgements = append(archive.Acknowledgements, archivedExecutionGap{ExecutionGapAcknowledgement: ExecutionGapAcknowledgement{ExecutionGap: s.executionGap(entry), Reviewer: "operator", ReviewReason: "Reviewed unavailable report with application records", AcknowledgedAt: time.Now().UTC(), RecordingStatus: "acknowledged_gap"}, Report: altered})
	if err := s.saveExecutionGapArchiveLocked(archive); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.observeQueuePath())
	if _, err := OpenExecutionGapReview(s.options.StateFile, s.options.OrganisationID, s.options.DeploymentID); err == nil {
		t.Fatal("changed signed receipt accepted")
	}
	after, _ := os.ReadFile(s.observeQueuePath())
	if !bytes.Equal(before, after) {
		t.Fatal("invalid archive removed queued evidence")
	}
}

func TestExecutionGapChangedQueuedReceiptCannotUseOlderAcknowledgement(t *testing.T) {
	s, entry := executionGapFixture(t)
	archive, _ := s.loadExecutionGapArchiveLocked()
	archive.Acknowledgements = append(archive.Acknowledgements, archivedExecutionGap{ExecutionGapAcknowledgement: ExecutionGapAcknowledgement{ExecutionGap: s.executionGap(entry), Reviewer: "operator", ReviewReason: "Reviewed unavailable report with application records", AcknowledgedAt: time.Now().UTC(), RecordingStatus: "acknowledged_gap"}, Report: entry})
	if err := s.saveExecutionGapArchiveLocked(archive); err != nil {
		t.Fatal(err)
	}
	changed := s.observeQueue
	changed.Outcomes = append([]queuedExecutionOutcome{}, changed.Outcomes...)
	changed.Outcomes[0].Receipt.Proof.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := s.saveObserveQueueLocked(changed); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.observeQueuePath())
	if _, err := OpenExecutionGapReview(s.options.StateFile, s.options.OrganisationID, s.options.DeploymentID); err == nil {
		t.Fatal("changed queued signature was discarded under an older acknowledgement")
	}
	after, _ := os.ReadFile(s.observeQueuePath())
	if !bytes.Equal(before, after) {
		t.Fatal("conflicting evidence was removed")
	}
}
