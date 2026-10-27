package sidecar

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var approvalUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var approvalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type approvalClaim struct {
	ApprovalRequestID string        `json:"approvalRequestId"`
	ActionID          string        `json:"actionId"`
	InputSHA256       string        `json:"inputSha256"`
	KeySHA256         string        `json:"keySha256"`
	Proof             IdentityProof `json:"proof"`
}

type approvalPermit struct {
	PermitID  string    `json:"permitId"`
	ActionID  string    `json:"actionId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ApprovalPermitHandler forwards a fresh protected-executor claim using the
// sidecar-held deployment credential. It never retries an uncertain claim.
func ApprovalPermitHandler(syncer *Synchronizer, adapterToken string) http.Handler {
	return approvalPermitHandler(syncer, adapterToken, false)
}

// ApprovalPermitRecoveryHandler reads a previously claimed permit without
// issuing another claim. Only the authenticated adapter can ask for it.
func ApprovalPermitRecoveryHandler(syncer *Synchronizer, adapterToken string) http.Handler {
	return approvalPermitHandler(syncer, adapterToken, true)
}

func approvalPermitHandler(syncer *Synchronizer, adapterToken string, recoverExisting bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authorization := r.Header.Get("Authorization")
		supplied := strings.TrimPrefix(authorization, "Bearer ")
		if len(r.Header.Values("Authorization")) != 1 ||
			!strings.HasPrefix(authorization, "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(supplied), []byte(adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		traceparent, valid := requestTraceparent(r)
		if !valid {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var claim approvalClaim
		if decoder.Decode(&claim) != nil || !approvalUUID.MatchString(claim.ApprovalRequestID) ||
			!approvalUUID.MatchString(claim.ActionID) ||
			!approvalDigest.MatchString(claim.InputSHA256) ||
			!approvalDigest.MatchString(claim.KeySHA256) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(claim)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		operation := "claim"
		expectedStatus := http.StatusCreated
		if recoverExisting {
			operation = "recover"
			expectedStatus = http.StatusOK
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(syncer.options.ControlPlaneURL, "/")+
				"/runtime/deployment/approval-permits/"+operation, bytes.NewReader(body))
		if err != nil || syncer.options.Token == "" || syncer.options.ControlPlaneURL == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		request.Header.Set("Authorization", "Bearer "+syncer.options.Token)
		request.Header.Set("Content-Type", "application/json")
		if traceparent != "" {
			request.Header.Set("traceparent", traceparent)
		}
		response, err := syncer.options.Client.Do(request)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != expectedStatus {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var permit approvalPermit
		if json.NewDecoder(io.LimitReader(response.Body, 2048)).Decode(&permit) != nil ||
			!approvalUUID.MatchString(permit.PermitID) || permit.ActionID != claim.ActionID ||
			!permit.ExpiresAt.After(time.Now()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expectedStatus)
		_ = json.NewEncoder(w).Encode(permit)
	})
}
