package sidecar

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(supplied), []byte(adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
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
		evaluation, err := syncer.Evaluate(request)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evaluation)
	})
}
