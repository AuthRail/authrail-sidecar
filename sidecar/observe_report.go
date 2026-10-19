package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type retainedObserve struct {
	ActionID      string `json:"actionId"`
	CertificateID string `json:"certificateId"`
	Replayed      bool   `json:"replayed"`
}

var errExecutorKeyClosed = errors.New("application key no longer accepts reports")

// retainObserve sends digests and decision metadata, never tool arguments or results.
// Failure is visible in the local response and cannot change the customer's tool call.
func (s *Synchronizer) retainObserve(ctx context.Context, actionKey string,
	request EvaluationRequest, evaluation Evaluation) (retainedObserve, string) {
	var retained retainedObserve
	if s.options.Token == "" || s.options.ControlPlaneURL == "" ||
		evaluation.BundleID == nil || evaluation.Coverage != "evaluated" {
		return retained, "unavailable"
	}
	input, err := observeInputBytes(request)
	if err != nil {
		return retained, "unavailable"
	}
	digest := sha256.Sum256(input)
	body, err := json.Marshal(struct {
		FormatVersion        int                  `json:"formatVersion"`
		InputSHA256          string               `json:"inputSha256"`
		Attribution          Attribution          `json:"attribution"`
		IdentityVerification IdentityVerification `json:"identityVerification"`
		ExecutorProof        IdentityProof        `json:"executorProof"`
		Report               struct {
			OperationVersionID string     `json:"operationVersionId"`
			Phase              string     `json:"phase"`
			Evaluation         Evaluation `json:"evaluation"`
		} `json:"report"`
	}{FormatVersion: 1, InputSHA256: hex.EncodeToString(digest[:]),
		Attribution: request.Attribution, IdentityVerification: s.identityVerification(request, actionKey),
		ExecutorProof: request.IdentityProof, Report: struct {
			OperationVersionID string     `json:"operationVersionId"`
			Phase              string     `json:"phase"`
			Evaluation         Evaluation `json:"evaluation"`
		}{request.OperationVersionID, request.Phase, evaluation}})
	if err != nil {
		return retained, "unavailable"
	}
	entry := queuedObserve{ActionKey: actionKey, Phase: request.Phase, Body: body}
	entry, err = s.enqueueObserve(entry)
	if err != nil {
		return retained, "unavailable"
	}
	if entry.BlockedReason != "" {
		return retained, "unavailable"
	}
	fastCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 750*time.Millisecond)
	defer cancel()
	retained, err = s.sendObserve(fastCtx, entry)
	if err != nil {
		if errors.Is(err, errExecutorKeyClosed) {
			_ = s.blockObserve(entry)
			return retainedObserve{}, "unavailable"
		}
		return retainedObserve{}, "queued"
	}
	_ = s.acknowledgeObserve(entry)
	return retained, "retained"
}

func (s *Synchronizer) sendObserve(ctx context.Context, entry queuedObserve) (retainedObserve, error) {
	var retained retainedObserve
	base := strings.TrimRight(s.options.ControlPlaneURL, "/")
	reportCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(reportCtx, http.MethodPost,
		base+"/runtime/deployment/observations", bytes.NewReader(entry.Body))
	if err != nil {
		return retained, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+s.options.Token)
	httpRequest.Header.Set("Idempotency-Key", entry.ActionKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := s.options.Client.Do(httpRequest)
	if err != nil {
		return retained, errors.New("control plane is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		if response.StatusCode == http.StatusConflict {
			var problem struct {
				Code string `json:"code"`
			}
			if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&problem) == nil &&
				problem.Code == "EXECUTOR_KEY_CLOSED" {
				return retained, errExecutorKeyClosed
			}
		}
		return retained, errors.New("control plane did not retain the Observe report")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&retained); err != nil ||
		!uuidPattern.MatchString(retained.ActionID) ||
		!uuidPattern.MatchString(retained.CertificateID) {
		return retainedObserve{}, errors.New("control plane receipt is invalid")
	}
	return retained, nil
}

func observeInputBytes(request EvaluationRequest) ([]byte, error) {
	arguments, err := object(request.Arguments)
	if err != nil {
		return nil, err
	}
	if request.Phase == "tool_call" {
		return json.Marshal(struct {
			Arguments       map[string]any      `json:"arguments"`
			FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
			Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
		}{arguments, request.FactResolutions, request.Trajectory})
	}
	if request.Phase == "tool_result" {
		result, err := object(request.Result)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Arguments       map[string]any      `json:"arguments"`
			Result          map[string]any      `json:"result"`
			FactResolutions []FactResolution    `json:"factResolutions,omitempty"`
			Trajectory      *TrajectorySnapshot `json:"trajectory,omitempty"`
		}{arguments, result, request.FactResolutions, request.Trajectory})
	}
	return nil, errors.New("Observe phase is invalid")
}
