package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

const maxTrajectorySessions = 128
const maxTrajectoryResults = 256
const maxTrajectoryLedgerBytes = 8 * 1024 * 1024

type trajectoryReadResult struct {
	RequestID          string `json:"requestId"`
	ActionKey          string `json:"actionKey"`
	OperationVersionID string `json:"operationVersionId"`
	InputSHA256        string `json:"inputSha256"`
	BundleID           string `json:"bundleId"`
	Sequence           int64  `json:"sequence"`
}

type trajectorySession struct {
	PrincipalID    string                 `json:"principalId"`
	SessionID      string                 `json:"sessionId"`
	StartRequestID string                 `json:"startRequestId"`
	Gap            bool                   `json:"gap"`
	Reads          []string               `json:"reads"`
	Calls          []trajectoryReadResult `json:"calls"`
	Results        []trajectoryReadResult `json:"results"`
}

type trajectoryLedger struct {
	FormatVersion  int                 `json:"formatVersion"`
	OrganisationID string              `json:"organisationId"`
	DeploymentID   string              `json:"deploymentId"`
	Sessions       []trajectorySession `json:"sessions"`
}

func (s *Synchronizer) trajectoryLedgerPath() string { return s.options.StateFile + ".trajectory" }

// loadTrajectoryLedgerLocked fails closed if a started ledger disappears;
// otherwise a restart could make an incomplete session look complete.
func (s *Synchronizer) loadTrajectoryLedgerLocked() error {
	if s.trajectoryLoaded {
		if s.trajectoryState.Sessions != nil && len(s.trajectoryState.Sessions) > 0 {
			info, err := os.Lstat(s.trajectoryLedgerPath())
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
				info.Size() > maxTrajectoryLedgerBytes {
				return errors.New("trajectory history is unavailable")
			}
		}
		return nil
	}
	state := trajectoryLedger{FormatVersion: 1, OrganisationID: s.options.OrganisationID,
		DeploymentID: s.options.DeploymentID, Sessions: []trajectorySession{}}
	info, err := os.Lstat(s.trajectoryLedgerPath())
	if errors.Is(err, os.ErrNotExist) {
		s.mu.RLock()
		started := s.state.TrajectoryLedgerStarted
		s.mu.RUnlock()
		if started {
			return errors.New("trajectory history is unavailable")
		}
		s.trajectoryState = state
		s.trajectoryLoaded = true
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() > maxTrajectoryLedgerBytes {
		return errors.New("trajectory history is unavailable")
	}
	data, err := os.ReadFile(s.trajectoryLedgerPath())
	if err != nil || json.Unmarshal(data, &state) != nil || state.FormatVersion != 1 ||
		state.OrganisationID != s.options.OrganisationID || state.DeploymentID != s.options.DeploymentID ||
		len(state.Sessions) > maxTrajectorySessions {
		return errors.New("trajectory history is invalid")
	}
	seen := make(map[string]struct{}, len(state.Sessions))
	for _, session := range state.Sessions {
		key := session.PrincipalID + "\x00" + session.SessionID
		if !identityRefPattern.MatchString(session.PrincipalID) ||
			!identityRefPattern.MatchString(session.SessionID) ||
			!uuidPattern.MatchString(session.StartRequestID) ||
			len(session.Reads) > maxTrajectoryResults || len(session.Calls) > maxTrajectoryResults ||
			len(session.Results) > maxTrajectoryResults {
			return errors.New("trajectory history is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("trajectory history is invalid")
		}
		seen[key] = struct{}{}
		reads := make(map[string]struct{}, len(session.Reads))
		for _, versionID := range session.Reads {
			if !uuidPattern.MatchString(versionID) {
				return errors.New("trajectory history is invalid")
			}
			if _, duplicate := reads[versionID]; duplicate {
				return errors.New("trajectory history is invalid")
			}
			reads[versionID] = struct{}{}
		}
		results := make(map[string]struct{}, len(session.Results))
		derivedReads := make([]string, 0, len(session.Reads))
		calls := make(map[string]trajectoryReadResult, len(session.Calls))
		for _, call := range session.Calls {
			if !validTrajectoryHook(call) {
				return errors.New("trajectory history is invalid")
			}
			if _, duplicate := calls[call.RequestID]; duplicate {
				return errors.New("trajectory history is invalid")
			}
			calls[call.RequestID] = call
		}
		for _, result := range session.Results {
			if !validTrajectoryHook(result) {
				return errors.New("trajectory history is invalid")
			}
			call, exists := calls[result.RequestID]
			if !exists || call.ActionKey != result.ActionKey ||
				call.OperationVersionID != result.OperationVersionID ||
				call.BundleID != result.BundleID || call.Sequence != result.Sequence {
				return errors.New("trajectory history is invalid")
			}
			if _, duplicate := results[result.RequestID]; duplicate {
				return errors.New("trajectory history is invalid")
			}
			results[result.RequestID] = struct{}{}
			if !contains(derivedReads, result.OperationVersionID) {
				derivedReads = append(derivedReads, result.OperationVersionID)
			}
		}
		if len(derivedReads) != len(session.Reads) {
			return errors.New("trajectory history is invalid")
		}
		for index, versionID := range derivedReads {
			if versionID != session.Reads[index] {
				return errors.New("trajectory history is invalid")
			}
		}
	}
	s.trajectoryState = state
	s.trajectoryLoaded = true
	return nil
}

func validTrajectoryHook(hook trajectoryReadResult) bool {
	if !uuidPattern.MatchString(hook.RequestID) || !actionKeyPattern.MatchString(hook.ActionKey) ||
		!uuidPattern.MatchString(hook.OperationVersionID) || !uuidPattern.MatchString(hook.BundleID) ||
		hook.Sequence < 1 || len(hook.InputSHA256) != 64 {
		return false
	}
	_, err := hex.DecodeString(hook.InputSHA256)
	return err == nil
}

func (s *Synchronizer) saveTrajectoryLedgerLocked(next trajectoryLedger) error {
	data, err := json.Marshal(next)
	if err != nil || len(data) > maxTrajectoryLedgerBytes {
		return errors.New("trajectory history is full")
	}
	s.mu.Lock()
	if !s.state.TrajectoryLedgerStarted {
		state := s.state
		state.TrajectoryLedgerStarted = true
		if err := saveState(s.options.StateFile, state); err != nil {
			s.mu.Unlock()
			return errors.New("trajectory history cannot be saved")
		}
		s.state = state
	}
	s.mu.Unlock()
	if err := savePrivateState(s.trajectoryLedgerPath(), data); err != nil {
		return errors.New("trajectory history cannot be saved")
	}
	s.trajectoryState = next
	return nil
}

func (s *Synchronizer) trajectorySessionLocked(principalID, sessionID string) int {
	for index, session := range s.trajectoryState.Sessions {
		if session.PrincipalID == principalID && session.SessionID == sessionID {
			return index
		}
	}
	return -1
}

func (s *Synchronizer) verifyTrajectoryLocked(request *EvaluationRequest, actionKey string) error {
	if request.Trajectory != nil {
		request.Trajectory.verified = false
	}
	if !validTrajectory(request.Trajectory, request.Attribution.SessionID) {
		return errors.New("trajectory snapshot is invalid")
	}
	if err := s.loadTrajectoryLedgerLocked(); err != nil {
		return err
	}
	snapshot := request.Trajectory
	if snapshot == nil || !snapshot.Complete {
		return nil
	}
	index := s.trajectorySessionLocked(request.Attribution.PrincipalID, request.Attribution.SessionID)
	if index < 0 {
		if !snapshot.Start || request.Phase != "tool_call" ||
			len(snapshot.PriorReadOperationVersionIDs) != 0 ||
			len(s.trajectoryState.Sessions) >= maxTrajectorySessions {
			return errors.New("trajectory history is unavailable")
		}
		next := s.trajectoryState
		next.Sessions = append(append([]trajectorySession(nil), next.Sessions...), trajectorySession{
			PrincipalID: request.Attribution.PrincipalID, SessionID: snapshot.SessionID,
			StartRequestID: request.RequestID, Reads: []string{},
			Calls: []trajectoryReadResult{}, Results: []trajectoryReadResult{}})
		if err := s.saveTrajectoryLedgerLocked(next); err != nil {
			return err
		}
		index = len(s.trajectoryState.Sessions) - 1
	}
	session := s.trajectoryState.Sessions[index]
	if session.Gap || (snapshot.Start && session.StartRequestID != request.RequestID) {
		return errors.New("trajectory history is unavailable")
	}
	if request.Phase == "tool_call" {
		for _, previous := range session.Calls {
			if previous.RequestID == request.RequestID {
				input, err := observeInputBytes(*request)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(input)
				if previous.ActionKey != actionKey || previous.OperationVersionID != request.OperationVersionID ||
					previous.InputSHA256 != hex.EncodeToString(digest[:]) {
					return errors.New("trajectory call replay changed")
				}
				snapshot.verified = true
				return nil
			}
		}
	}
	if request.Phase == "tool_result" {
		for _, previous := range session.Results {
			if previous.RequestID == request.RequestID {
				input, err := observeInputBytes(*request)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(input)
				if previous.ActionKey != actionKey || previous.OperationVersionID != request.OperationVersionID ||
					previous.InputSHA256 != hex.EncodeToString(digest[:]) {
					return errors.New("trajectory result replay changed")
				}
				snapshot.verified = true
				return nil
			}
		}
	}
	if len(snapshot.PriorReadOperationVersionIDs) != len(session.Reads) {
		return errors.New("trajectory history is incomplete")
	}
	for index, versionID := range session.Reads {
		if snapshot.PriorReadOperationVersionIDs[index] != versionID {
			return errors.New("trajectory history is incomplete")
		}
	}
	snapshot.verified = true
	return nil
}

func (s *Synchronizer) markTrajectoryGapLocked(request EvaluationRequest) error {
	if err := s.loadTrajectoryLedgerLocked(); err != nil {
		return err
	}
	next := s.trajectoryState
	next.Sessions = append([]trajectorySession(nil), next.Sessions...)
	index := s.trajectorySessionLocked(request.Attribution.PrincipalID, request.Attribution.SessionID)
	if index < 0 {
		if len(next.Sessions) >= maxTrajectorySessions {
			return errors.New("trajectory history is full")
		}
		next.Sessions = append(next.Sessions, trajectorySession{
			PrincipalID: request.Attribution.PrincipalID, SessionID: request.Attribution.SessionID,
			StartRequestID: request.RequestID, Gap: true,
			Reads: []string{}, Calls: []trajectoryReadResult{}, Results: []trajectoryReadResult{}})
	} else {
		if next.Sessions[index].Gap {
			return nil
		}
		next.Sessions[index].Gap = true
	}
	return s.saveTrajectoryLedgerLocked(next)
}

func (s *Synchronizer) recordTrajectoryResultLocked(request EvaluationRequest,
	actionKey string, evaluation Evaluation) error {
	if !evaluation.readResult && !evaluation.readCall {
		return nil
	}
	if evaluation.Coverage != "evaluated" {
		return errors.New("trajectory read hook was not covered")
	}
	if evaluation.BundleID == nil {
		return errors.New("trajectory read bundle is unavailable")
	}
	index := s.trajectorySessionLocked(request.Attribution.PrincipalID, request.Attribution.SessionID)
	if index < 0 || request.Trajectory == nil || !request.Trajectory.verified {
		return errors.New("trajectory read result was not covered")
	}
	input, err := observeInputBytes(request)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(input)
	value := trajectoryReadResult{RequestID: request.RequestID, ActionKey: actionKey,
		OperationVersionID: request.OperationVersionID, InputSHA256: hex.EncodeToString(digest[:]),
		BundleID: *evaluation.BundleID, Sequence: evaluation.Sequence}
	session := s.trajectoryState.Sessions[index]
	if evaluation.readCall {
		for _, previous := range session.Calls {
			if previous.RequestID == request.RequestID {
				if previous == value {
					return nil
				}
				return errors.New("trajectory call replay changed")
			}
		}
		if len(session.Calls) >= maxTrajectoryResults {
			return errors.New("trajectory history is full")
		}
		next := s.trajectoryState
		next.Sessions = append([]trajectorySession(nil), next.Sessions...)
		session.Calls = append(append([]trajectoryReadResult(nil), session.Calls...), value)
		next.Sessions[index] = session
		return s.saveTrajectoryLedgerLocked(next)
	}
	var matchedCall bool
	for _, previous := range session.Calls {
		if previous.RequestID == request.RequestID && previous.ActionKey == actionKey &&
			previous.OperationVersionID == request.OperationVersionID &&
			previous.BundleID == value.BundleID && previous.Sequence == value.Sequence {
			matchedCall = true
			break
		}
	}
	if !matchedCall {
		return errors.New("trajectory result has no matching call")
	}
	for _, previous := range session.Results {
		if previous.RequestID == request.RequestID {
			if previous == value {
				return nil
			}
			return errors.New("trajectory result replay changed")
		}
	}
	if len(session.Results) >= maxTrajectoryResults {
		return errors.New("trajectory history is full")
	}
	next := s.trajectoryState
	next.Sessions = append([]trajectorySession(nil), next.Sessions...)
	session.Results = append(append([]trajectoryReadResult(nil), session.Results...), value)
	if !contains(session.Reads, request.OperationVersionID) {
		if len(session.Reads) >= maxTrajectoryResults {
			return errors.New("trajectory history is full")
		}
		session.Reads = append(append([]string(nil), session.Reads...), request.OperationVersionID)
	}
	next.Sessions[index] = session
	return s.saveTrajectoryLedgerLocked(next)
}
