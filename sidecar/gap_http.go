package sidecar

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// OperatorGapHandler exposes only local, metadata-only recording gaps. The
// operator token must never be shared with an agent or the adapter.
func OperatorGapHandler(s *Synchronizer, operatorToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
			len(supplied) != len(operatorToken) ||
			subtle.ConstantTimeCompare([]byte(supplied), []byte(operatorToken)) != 1 {
			gapError(w, http.StatusUnauthorized, "Operator access required.")
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/observations/gaps":
			gaps, err := s.ReviewObservationGaps()
			if err != nil {
				gapUnavailable(w)
				return
			}
			_ = json.NewEncoder(w).Encode(struct {
				Gaps []ObservationGap `json:"gaps"`
			}{gaps})
		case r.Method == http.MethodGet && r.URL.Path == "/observations/gaps/history":
			history, err := s.GapHistory()
			if err != nil {
				gapUnavailable(w)
				return
			}
			_ = json.NewEncoder(w).Encode(struct {
				Acknowledgements []GapAcknowledgement `json:"acknowledgements"`
			}{history})
		case r.Method == http.MethodPost && r.URL.Path == "/observations/gaps/acknowledgements":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				gapError(w, http.StatusUnsupportedMediaType, "Send JSON.")
				return
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
			decoder.DisallowUnknownFields()
			var input AcknowledgeGapInput
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
				gapError(w, http.StatusBadRequest, "Review details are invalid.")
				return
			}
			ack, err := s.AcknowledgeObservationGap(input)
			if err != nil {
				status := http.StatusServiceUnavailable
				if errors.Is(err, ErrGapInvalid) {
					status = http.StatusBadRequest
				}
				if errors.Is(err, ErrGapNotFound) {
					status = http.StatusNotFound
				}
				if errors.Is(err, ErrGapChanged) {
					status = http.StatusConflict
				}
				gapError(w, status, "Recording gap could not be acknowledged.")
				return
			}
			_ = json.NewEncoder(w).Encode(ack)
		default:
			http.NotFound(w, r)
		}
	})
}

func gapUnavailable(w http.ResponseWriter) {
	gapError(w, http.StatusServiceUnavailable, "Recording gaps are temporarily unavailable.")
}

func gapError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
