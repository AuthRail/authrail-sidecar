package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

const maxGapLedgerBytes = 16 * 1024 * 1024

var ErrGapNotFound = errors.New("blocked Observe report was not found")
var ErrGapChanged = errors.New("blocked Observe report changed; review it again")
var ErrGapInvalid = errors.New("gap acknowledgement is invalid")

// ObservationGap is local metadata for a report AuthRail did not retain.
type ObservationGap struct {
	ActionKey         string `json:"actionKey"`
	Phase             string `json:"phase"`
	InputSHA256       string `json:"inputSha256"`
	ExecutorKeySHA256 string `json:"executorKeySha256,omitempty"`
	Reason            string `json:"reason"`
}

type GapAcknowledgement struct {
	ObservationGap
	ReviewReason   string    `json:"reviewReason"`
	AcknowledgedAt time.Time `json:"acknowledgedAt"`
}

type gapLedgerState struct {
	FormatVersion   int                  `json:"formatVersion"`
	OrganisationID  string               `json:"organisationId"`
	DeploymentID    string               `json:"deploymentId"`
	Acknowledgments []GapAcknowledgement `json:"acknowledgements"`
}

type AcknowledgeGapInput struct {
	ActionKey   string `json:"actionKey"`
	Phase       string `json:"phase"`
	InputSHA256 string `json:"inputSha256"`
	Reason      string `json:"reason"`
}

func (s *Synchronizer) gapLedgerPath() string { return s.options.StateFile + ".observation-gaps" }

func gapFromQueued(entry queuedObserve) (ObservationGap, error) {
	var body struct {
		InputSHA256          string                `json:"inputSha256"`
		IdentityVerification *IdentityVerification `json:"identityVerification"`
	}
	if entry.BlockedReason != "application_key_closed" ||
		json.Unmarshal(entry.Body, &body) != nil || len(body.InputSHA256) != 64 {
		return ObservationGap{}, errors.New("blocked Observe report is invalid")
	}
	gap := ObservationGap{ActionKey: entry.ActionKey, Phase: entry.Phase,
		InputSHA256: body.InputSHA256, Reason: entry.BlockedReason}
	if body.IdentityVerification != nil {
		gap.ExecutorKeySHA256 = body.IdentityVerification.KeySHA256
	}
	return gap, nil
}

func (s *Synchronizer) ReviewObservationGaps() ([]ObservationGap, error) {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return nil, err
	}
	gaps := make([]ObservationGap, 0)
	for _, entry := range s.observeQueue.Entries {
		if entry.BlockedReason == "" {
			continue
		}
		gap, err := gapFromQueued(entry)
		if err != nil {
			return nil, err
		}
		gaps = append(gaps, gap)
	}
	return gaps, nil
}

func (s *Synchronizer) loadGapLedgerLocked() (gapLedgerState, error) {
	state := gapLedgerState{FormatVersion: 1,
		OrganisationID: s.options.OrganisationID, DeploymentID: s.options.DeploymentID,
		Acknowledgments: []GapAcknowledgement{}}
	info, err := os.Lstat(s.gapLedgerPath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() > maxGapLedgerBytes {
		return state, errors.New("Observe gap history is inaccessible or unsafe")
	}
	data, err := os.ReadFile(s.gapLedgerPath())
	if err != nil || json.Unmarshal(data, &state) != nil || state.FormatVersion != 1 ||
		state.OrganisationID != s.options.OrganisationID ||
		state.DeploymentID != s.options.DeploymentID || state.Acknowledgments == nil {
		return state, errors.New("Observe gap history is invalid")
	}
	seen := make(map[string]struct{}, len(state.Acknowledgments))
	for _, item := range state.Acknowledgments {
		key := item.ActionKey + "\x00" + item.Phase + "\x00" + item.InputSHA256
		if !actionKeyPattern.MatchString(item.ActionKey) ||
			(item.Phase != "tool_call" && item.Phase != "tool_result") ||
			len(item.InputSHA256) != 64 || item.Reason != "application_key_closed" ||
			len(item.ReviewReason) < 8 || len(item.ReviewReason) > 500 ||
			item.AcknowledgedAt.IsZero() {
			return state, errors.New("Observe gap history is invalid")
		}
		if _, err := hex.DecodeString(item.InputSHA256); err != nil {
			return state, errors.New("Observe gap history is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return state, errors.New("Observe gap history has duplicate entries")
		}
		seen[key] = struct{}{}
	}
	return state, nil
}

func (s *Synchronizer) saveGapLedgerLocked(state gapLedgerState) error {
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxGapLedgerBytes {
		return errors.New("Observe gap history is full")
	}
	return savePrivateState(s.gapLedgerPath(), data)
}

// AcknowledgeObservationGap records a local review before freeing queue space.
// A crash between the two writes is recovered on restart or a repeated request.
func (s *Synchronizer) AcknowledgeObservationGap(input AcknowledgeGapInput) (GapAcknowledgement, error) {
	reason := strings.TrimSpace(input.Reason)
	if !actionKeyPattern.MatchString(input.ActionKey) ||
		(input.Phase != "tool_call" && input.Phase != "tool_result") ||
		len(input.InputSHA256) != 64 || len(reason) < 8 || len(reason) > 500 ||
		strings.ContainsAny(reason, "\r\n\x00") {
		return GapAcknowledgement{}, ErrGapInvalid
	}
	if _, err := hex.DecodeString(input.InputSHA256); err != nil {
		return GapAcknowledgement{}, ErrGapInvalid
	}
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	if err := s.ensureObserveQueueLocked(); err != nil {
		return GapAcknowledgement{}, err
	}
	ledger, err := s.loadGapLedgerLocked()
	if err != nil {
		return GapAcknowledgement{}, err
	}
	index := -1
	var gap ObservationGap
	for i, entry := range s.observeQueue.Entries {
		if entry.ActionKey == input.ActionKey && entry.Phase == input.Phase {
			if entry.BlockedReason == "" {
				return GapAcknowledgement{}, ErrGapChanged
			}
			gap, err = gapFromQueued(entry)
			if err != nil {
				return GapAcknowledgement{}, err
			}
			if gap.InputSHA256 != input.InputSHA256 {
				return GapAcknowledgement{}, ErrGapChanged
			}
			index = i
			break
		}
	}
	var acknowledged *GapAcknowledgement
	for i := range ledger.Acknowledgments {
		item := &ledger.Acknowledgments[i]
		if item.ActionKey == input.ActionKey && item.Phase == input.Phase &&
			item.InputSHA256 == input.InputSHA256 {
			if item.ReviewReason != reason {
				return GapAcknowledgement{}, ErrGapChanged
			}
			acknowledged = item
			break
		}
	}
	if index < 0 {
		if acknowledged != nil {
			return *acknowledged, nil
		}
		return GapAcknowledgement{}, ErrGapNotFound
	}
	if acknowledged == nil {
		now := s.options.Now
		if now == nil {
			now = time.Now
		}
		item := GapAcknowledgement{ObservationGap: gap,
			ReviewReason: reason, AcknowledgedAt: now().UTC()}
		ledger.Acknowledgments = append(ledger.Acknowledgments, item)
		if err := s.saveGapLedgerLocked(ledger); err != nil {
			return GapAcknowledgement{}, err
		}
		acknowledged = &item
	}
	next := s.observeQueue
	next.Entries = append(append([]queuedObserve{}, s.observeQueue.Entries[:index]...),
		s.observeQueue.Entries[index+1:]...)
	if err := s.saveObserveQueueLocked(next); err != nil {
		return GapAcknowledgement{}, err
	}
	s.observeQueue = next
	return *acknowledged, nil
}

func (s *Synchronizer) reconcileAcknowledgedGapsLocked() error {
	ledger, err := s.loadGapLedgerLocked()
	if err != nil {
		return err
	}
	if len(ledger.Acknowledgments) == 0 {
		return nil
	}
	acknowledged := make(map[string]struct{}, len(ledger.Acknowledgments))
	for _, item := range ledger.Acknowledgments {
		acknowledged[item.ActionKey+"\x00"+item.Phase+"\x00"+item.InputSHA256] = struct{}{}
	}
	next := s.observeQueue
	next.Entries = make([]queuedObserve, 0, len(s.observeQueue.Entries))
	for _, entry := range s.observeQueue.Entries {
		if entry.BlockedReason != "" {
			gap, err := gapFromQueued(entry)
			if err != nil {
				return err
			}
			if _, found := acknowledged[gap.ActionKey+"\x00"+gap.Phase+"\x00"+gap.InputSHA256]; found {
				continue
			}
		}
		next.Entries = append(next.Entries, entry)
	}
	if len(next.Entries) == len(s.observeQueue.Entries) {
		return nil
	}
	if err := s.saveObserveQueueLocked(next); err != nil {
		return err
	}
	s.observeQueue = next
	return nil
}

// The ledger contains only metadata. A raw report remains exclusively in the
// queue until acknowledgement; neither file ever stores tool input or result.
func (s *Synchronizer) GapHistory() ([]GapAcknowledgement, error) {
	s.observeMu.Lock()
	defer s.observeMu.Unlock()
	ledger, err := s.loadGapLedgerLocked()
	if err != nil {
		return nil, err
	}
	start := len(ledger.Acknowledgments) - 100
	if start < 0 {
		start = 0
	}
	return append([]GapAcknowledgement(nil), ledger.Acknowledgments[start:]...), nil
}
