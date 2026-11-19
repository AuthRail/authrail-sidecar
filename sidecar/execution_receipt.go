package sidecar

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type executionReceipt struct {
	ActionID               string        `json:"actionId"`
	AttemptID              string        `json:"attemptId"`
	PermitID               *string       `json:"permitId"`
	Event                  string        `json:"event"`
	InputSHA256            string        `json:"inputSha256"`
	ProviderIdempotencyKey string        `json:"providerIdempotencyKey"`
	ProviderReference      *string       `json:"providerReference"`
	KeySHA256              string        `json:"keySha256"`
	Proof                  IdentityProof `json:"proof"`
}

// ExecutionReceiptHandler forwards bounded signed executor claims. It never
// invents an outcome or retries an uncertain report on the executor's behalf.
func ExecutionReceiptHandler(syncer *Synchronizer, adapterToken string, telemetry ...*Telemetry) http.Handler {
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
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var receipt executionReceipt
		if decoder.Decode(&receipt) != nil || !approvalUUID.MatchString(receipt.ActionID) ||
			!approvalUUID.MatchString(receipt.AttemptID) ||
			(receipt.PermitID != nil && !approvalUUID.MatchString(*receipt.PermitID)) ||
			!approvalDigest.MatchString(receipt.InputSHA256) ||
			!approvalDigest.MatchString(receipt.KeySHA256) ||
			!actionKeyPattern.MatchString(receipt.ProviderIdempotencyKey) ||
			(receipt.ProviderReference != nil &&
				!validProviderReference(*receipt.ProviderReference)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch receipt.Event {
		case "started", "succeeded", "failed", "unknown", "reconciled_succeeded", "reconciled_failed":
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if receipt.Event == "started" && receipt.ProviderReference != nil ||
			strings.HasPrefix(receipt.Event, "reconciled_") && receipt.ProviderReference == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		idempotencyKey := receipt.ActionID + ":" + receipt.AttemptID + ":" + receipt.Event
		if len(r.Header.Values("Idempotency-Key")) != 1 ||
			r.Header.Get("Idempotency-Key") != idempotencyKey {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(receipt)
		if err != nil || syncer.options.Token == "" || syncer.options.ControlPlaneURL == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(syncer.options.ControlPlaneURL, "/")+
				"/runtime/deployment/execution-receipts", bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		request.Header.Set("Authorization", "Bearer "+syncer.options.Token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", idempotencyKey)
		if traceparent != "" {
			request.Header.Set("traceparent", traceparent)
		}
		response, err := syncer.options.Client.Do(request)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var retained struct {
			ReceiptID string `json:"receiptId"`
			State     string `json:"state"`
			Replayed  bool   `json:"replayed"`
		}
		if decodeControlPlaneResponse(response.Body, 2048, &retained) != nil ||
			!approvalUUID.MatchString(retained.ReceiptID) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if len(telemetry) > 0 {
			telemetry[0].recordExecution(receipt.ActionID, receipt.AttemptID, receipt.Event, "retained")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(retained)
	})
}

// A reference is retained evidence only; it must never select an execution endpoint.
func validProviderReference(value string) bool {
	if len(value) < 1 || len(value) > 4000 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}
	return true
}
