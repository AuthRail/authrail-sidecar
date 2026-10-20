package sidecar

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var actionKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var identityRefPattern = actionKeyPattern

// EvaluationHandler accepts only requests from the protected local adapter.
// The deployment credential is never accepted on this listener.
func EvaluationHandler(syncer *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(r.Header.Values("Authorization")) != 1 ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(supplied), []byte(adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 ||
			!actionKeyPattern.MatchString(r.Header.Get("Idempotency-Key")) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		var request EvaluationRequest
		if err := decoder.Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !identityRefPattern.MatchString(request.Attribution.PrincipalID) ||
			!identityRefPattern.MatchString(request.Attribution.SessionID) ||
			(request.Attribution.ResourceID != nil &&
				!identityRefPattern.MatchString(*request.Attribution.ResourceID)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := syncer.verifyIdentityProof(request, r.Header.Get("Idempotency-Key")); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		syncer.trajectoryMu.Lock()
		if err := syncer.verifyTrajectoryLocked(&request, r.Header.Get("Idempotency-Key")); err != nil {
			syncer.trajectoryMu.Unlock()
			writeTrajectoryUnavailable(w, request.RequestID)
			return
		}
		evaluation, err := syncer.Evaluate(request)
		if err != nil {
			syncer.trajectoryMu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := syncer.recordTrajectoryResultLocked(request, r.Header.Get("Idempotency-Key"), evaluation); err != nil {
			_ = syncer.markTrajectoryGapLocked(request)
			syncer.trajectoryMu.Unlock()
			writeTrajectoryUnavailable(w, request.RequestID)
			return
		}
		syncer.trajectoryMu.Unlock()
		if retained, status := syncer.retainObserve(r.Context(),
			r.Header.Get("Idempotency-Key"), request, evaluation); status == "retained" {
			evaluation.RecordingStatus = status
			evaluation.ActionID = retained.ActionID
			evaluation.CertificateID = retained.CertificateID
		} else {
			evaluation.RecordingStatus = status
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evaluation)
	})
}

func writeTrajectoryUnavailable(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Evaluation{RequestID: requestID, Mode: "observe",
		Enforced: false, Coverage: "unavailable", Outcome: "additional_context_required",
		ReasonCodes: []string{"trajectory_unverified"},
		Unresolved: []UnresolvedField{{Root: "trajectory",
			Path: []string{"priorReadOperationVersionIds"}, Reason: "unavailable"}},
		RecordingStatus: "unavailable"})
}
