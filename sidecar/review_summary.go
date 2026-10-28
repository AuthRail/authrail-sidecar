package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type ReviewSummary struct {
	Title  string               `json:"title"`
	Fields []ReviewSummaryField `json:"fields"`
}

type ReviewSummaryField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func validReviewText(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 32 || character == 127 || character == '<' ||
			character == '>' || character == '&' || character == '\u2028' ||
			character == '\u2029' {
			return false
		}
	}
	return true
}

// reviewSummaryDigest binds a bounded display summary to the executor proof.
func reviewSummaryDigest(summary *ReviewSummary) (string, error) {
	if summary == nil {
		return "", nil
	}
	if !validReviewText(summary.Title, 120) || len(summary.Fields) < 1 ||
		len(summary.Fields) > 8 {
		return "", errors.New("review summary is invalid")
	}
	for _, field := range summary.Fields {
		if !validReviewText(field.Label, 60) || !validReviewText(field.Value, 200) {
			return "", errors.New("review summary is invalid")
		}
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return "", errors.New("review summary is invalid")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
