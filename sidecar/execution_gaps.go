package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExecutionGap is metadata for an executor report not retained by AuthRail.
// Its fingerprint includes the deployment identity and complete signed receipt.
type ExecutionGap struct {
	Fingerprint        string `json:"fingerprint"`
	OperationVersionID string `json:"operationVersionId"`
	ActionKey          string `json:"actionKey"`
	AttemptID          string `json:"attemptId"`
	Event              string `json:"event"`
	InputSHA256        string `json:"inputSha256"`
	ExecutorKeySHA256  string `json:"executorKeySha256"`
}

type ExecutionGapAcknowledgement struct {
	ExecutionGap
	Reviewer        string    `json:"reviewer"`
	ReviewReason    string    `json:"reviewReason"`
	AcknowledgedAt  time.Time `json:"acknowledgedAt"`
	RecordingStatus string    `json:"recordingStatus"`
}

type archivedExecutionGap struct {
	ExecutionGapAcknowledgement
	Report queuedExecutionOutcome `json:"report"`
}

type executionGapArchive struct {
	FormatVersion    int                    `json:"formatVersion"`
	OrganisationID   string                 `json:"organisationId"`
	DeploymentID     string                 `json:"deploymentId"`
	Acknowledgements []archivedExecutionGap `json:"acknowledgements"`
}

// ExecutionGapReview is an offline host-operator tool. The caller must hold the
// state-file process lock and stop legacy daemons before opening it. It grants
// no Runtime permission and performs no control-plane or provider request.
type ExecutionGapReview struct{ synchronizer *Synchronizer }

func OpenExecutionGapReview(stateFile, organisationID, deploymentID string) (*ExecutionGapReview, error) {
	if !filepath.IsAbs(stateFile) || !uuidPattern.MatchString(organisationID) || !uuidPattern.MatchString(deploymentID) {
		return nil, errors.New("exact absolute state path and deployment identity are required")
	}
	info, err := os.Lstat(filepath.Dir(stateFile))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory is inaccessible or unsafe")
	}
	s := &Synchronizer{options: Options{StateFile: stateFile, OrganisationID: organisationID, DeploymentID: deploymentID, Now: time.Now}}
	if err := s.ensureObserveQueueLocked(); err != nil {
		return nil, err
	}
	return &ExecutionGapReview{synchronizer: s}, nil
}

func (s *Synchronizer) executionGapArchivePath() string {
	return s.options.StateFile + ".execution-gaps"
}

func (s *Synchronizer) executionGap(entry queuedExecutionOutcome) ExecutionGap {
	data, _ := json.Marshal(struct {
		OrganisationID string                   `json:"organisationId"`
		DeploymentID   string                   `json:"deploymentId"`
		Receipt        observedExecutionReceipt `json:"receipt"`
	}{s.options.OrganisationID, s.options.DeploymentID, entry.Receipt})
	sum := sha256.Sum256(data)
	r := entry.Receipt
	return ExecutionGap{hex.EncodeToString(sum[:]), r.OperationVersionID, r.ActionKey, r.AttemptID, r.Event, r.InputSHA256, r.KeySHA256}
}

func validExecutionGapReview(reviewer, reason string) bool {
	return reviewer == strings.TrimSpace(reviewer) && len(reviewer) > 0 && len(reviewer) <= 128 &&
		reason == strings.TrimSpace(reason) && len(reason) >= 8 && len(reason) <= 500 &&
		!strings.ContainsAny(reviewer+reason, "\r\n\x00")
}

func (s *Synchronizer) loadExecutionGapArchiveLocked() (executionGapArchive, error) {
	archive := executionGapArchive{FormatVersion: 1, OrganisationID: s.options.OrganisationID, DeploymentID: s.options.DeploymentID, Acknowledgements: []archivedExecutionGap{}}
	info, err := os.Lstat(s.executionGapArchivePath())
	if errors.Is(err, os.ErrNotExist) {
		return archive, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxGapLedgerBytes {
		return archive, errors.New("execution gap archive is inaccessible or unsafe")
	}
	data, err := os.ReadFile(s.executionGapArchivePath())
	if err != nil || json.Unmarshal(data, &archive) != nil || archive.FormatVersion != 1 || archive.OrganisationID != s.options.OrganisationID || archive.DeploymentID != s.options.DeploymentID || archive.Acknowledgements == nil {
		return archive, errors.New("execution gap archive is invalid")
	}
	seen := map[string]bool{}
	for _, item := range archive.Acknowledgements {
		if !validObservedReceipt(item.Report.Receipt) || !validTraceparent(item.Report.Traceparent) ||
			item.ExecutionGap != s.executionGap(item.Report) || !validExecutionGapReview(item.Reviewer, item.ReviewReason) ||
			item.AcknowledgedAt.IsZero() || item.RecordingStatus != "acknowledged_gap" || seen[outcomeKey(item.Report.Receipt)] {
			return archive, errors.New("execution gap archive receipt or review does not match")
		}
		seen[outcomeKey(item.Report.Receipt)] = true
	}
	return archive, nil
}

func (s *Synchronizer) saveExecutionGapArchiveLocked(archive executionGapArchive) error {
	data, err := json.Marshal(archive)
	if err != nil || len(data) > maxGapLedgerBytes {
		return errors.New("execution gap archive is full")
	}
	return savePrivateState(s.executionGapArchivePath(), data)
}

// List exposes only receipt identifiers/digests and local review metadata, never
// signatures, provider references, credentials or raw execution reports.
func (review *ExecutionGapReview) List() ([]ExecutionGap, []ExecutionGapAcknowledgement, error) {
	s := review.synchronizer
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	archive, err := s.loadExecutionGapArchiveLocked()
	if err != nil {
		return nil, nil, err
	}
	pending := make([]ExecutionGap, 0, len(s.observeQueue.Outcomes))
	for _, entry := range s.observeQueue.Outcomes {
		pending = append(pending, s.executionGap(entry))
	}
	acknowledged := make([]ExecutionGapAcknowledgement, 0, len(archive.Acknowledgements))
	for _, item := range archive.Acknowledgements {
		acknowledged = append(acknowledged, item.ExecutionGapAcknowledgement)
	}
	return pending, acknowledged, nil
}

// Acknowledge archives the complete unretained signed report and named review
// before freeing active retry space. It never reports central receipt retention
// or policy coverage. Repeating the same fingerprint/review is idempotent.
func (review *ExecutionGapReview) Acknowledge(fingerprint, reviewer, reason string) (ExecutionGapAcknowledgement, error) {
	var zero ExecutionGapAcknowledgement
	if !guardDigest.MatchString(fingerprint) || !validExecutionGapReview(reviewer, reason) {
		return zero, errors.New("exact fingerprint, reviewer and review reason are required")
	}
	s := review.synchronizer
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	archive, err := s.loadExecutionGapArchiveLocked()
	if err != nil {
		return zero, err
	}
	for _, item := range archive.Acknowledgements {
		if item.Fingerprint == fingerprint {
			if item.Reviewer != reviewer || item.ReviewReason != reason {
				return zero, errors.New("execution gap acknowledgement changed")
			}
			if err := s.reconcileExecutionGapsLocked(); err != nil {
				return zero, err
			}
			return item.ExecutionGapAcknowledgement, nil
		}
	}
	for _, entry := range s.observeQueue.Outcomes {
		gap := s.executionGap(entry)
		if gap.Fingerprint != fingerprint {
			continue
		}
		for _, existing := range archive.Acknowledgements {
			if outcomeKey(existing.Report.Receipt) == outcomeKey(entry.Receipt) {
				return zero, errors.New("execution gap report changed")
			}
		}
		ack := ExecutionGapAcknowledgement{ExecutionGap: gap, Reviewer: reviewer, ReviewReason: reason, AcknowledgedAt: time.Now().UTC(), RecordingStatus: "acknowledged_gap"}
		archive.Acknowledgements = append(archive.Acknowledgements, archivedExecutionGap{ack, entry})
		if err := s.saveExecutionGapArchiveLocked(archive); err != nil {
			return zero, err
		}
		if err := s.reconcileExecutionGapsLocked(); err != nil {
			return zero, err
		}
		return ack, nil
	}
	return zero, errors.New("queued execution report fingerprint was not found")
}

// reconcileExecutionGapsLocked completes archive-before-queue crash recovery.
// A changed signed receipt cannot be discarded under an older acknowledgement.
func (s *Synchronizer) reconcileExecutionGapsLocked() error {
	archive, err := s.loadExecutionGapArchiveLocked()
	if err != nil {
		return err
	}
	if len(archive.Acknowledgements) == 0 {
		return nil
	}
	acknowledged := map[string]string{}
	for _, item := range archive.Acknowledgements {
		acknowledged[outcomeKey(item.Report.Receipt)] = item.Fingerprint
	}
	next := s.observeQueue
	next.Outcomes = make([]queuedExecutionOutcome, 0, len(s.observeQueue.Outcomes))
	for _, entry := range s.observeQueue.Outcomes {
		if fingerprint, ok := acknowledged[outcomeKey(entry.Receipt)]; ok {
			if s.executionGap(entry).Fingerprint != fingerprint {
				return errors.New("queued execution report differs from archived acknowledgement")
			}
			continue
		}
		next.Outcomes = append(next.Outcomes, entry)
	}
	if len(next.Outcomes) == len(s.observeQueue.Outcomes) {
		return nil
	}
	if err := s.saveObserveQueueLocked(next); err != nil {
		return err
	}
	s.observeQueue = next
	return nil
}
