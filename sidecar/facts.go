package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"time"
)

var invoiceKeyPattern = regexp.MustCompile(`^in_[A-Za-z0-9]{4,100}$`)
var quickBooksKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

type FactResolution struct {
	SourceVersionID       string         `json:"sourceVersionId"`
	ProviderAccountID     string         `json:"providerAccountId,omitempty"`
	SourceIdentity        string         `json:"sourceIdentity,omitempty"`
	AccountBoundary       string         `json:"accountBoundary,omitempty"`
	Lookup                string         `json:"lookup"`
	LookupKey             string         `json:"lookupKey"`
	AuthenticatedExecutor bool           `json:"authenticatedExecutor"`
	Status                string         `json:"status"`
	ObservedAt            string         `json:"observedAt,omitempty"`
	Value                 map[string]any `json:"value,omitempty"`
}

type factContract struct {
	FormatVersion     int      `json:"formatVersion"`
	Provider          string   `json:"provider"`
	Kind              string   `json:"kind"`
	ProviderAccountID string   `json:"providerAccountId"`
	SourceIdentity    string   `json:"sourceIdentity"`
	AccountBoundary   string   `json:"accountBoundary"`
	Lookup            string   `json:"lookup"`
	QueryField        field    `json:"queryField"`
	FactKey           string   `json:"factKey"`
	ResultField       string   `json:"resultField"`
	ResultPath        []string `json:"resultPath"`
	ValueType         string   `json:"valueType"`
	MaxAgeSeconds     int      `json:"maxAgeSeconds"`
	TimeoutMs         int      `json:"timeoutMs"`
	Failure           string   `json:"failure"`
}

type FactSummary struct {
	SourceVersionID   string  `json:"sourceVersionId"`
	FactKey           string  `json:"factKey"`
	ProviderAccountID string  `json:"providerAccountId,omitempty"`
	SourceIdentity    string  `json:"sourceIdentity,omitempty"`
	AccountBoundary   string  `json:"accountBoundary,omitempty"`
	Lookup            string  `json:"lookup"`
	LookupKeySHA256   string  `json:"lookupKeySha256,omitempty"`
	Status            string  `json:"status"`
	ObservedAt        string  `json:"observedAt,omitempty"`
	AgeSeconds        float64 `json:"ageSeconds,omitempty"`
}

type resolvedFact struct {
	value   any
	status  string
	summary FactSummary
}

func resolveDataFact(rail railBinding, args map[string]any, resolutions []FactResolution,
	now time.Time) resolvedFact {
	contract := rail.SourceContextContract
	summary := FactSummary{SourceVersionID: rail.SourceContextVersionID,
		FactKey: contract.FactKey, ProviderAccountID: contract.ProviderAccountID,
		SourceIdentity: contract.SourceIdentity, AccountBoundary: contract.AccountBoundary,
		Lookup: contract.Lookup, Status: "unavailable"}
	output := resolvedFact{status: "unavailable", summary: summary}
	if !uuidPattern.MatchString(rail.SourceContextVersionID) || contract.FactKey == "" ||
		contract.Lookup == "" || contract.QueryField.Root != "arguments" ||
		contract.MaxAgeSeconds < 1 || contract.MaxAgeSeconds > 3600 ||
		contract.TimeoutMs < 100 || contract.TimeoutMs > 10000 || contract.Failure != "unavailable" {
		output.status, output.summary.Status = "untrusted", "untrusted"
		return output
	}
	keyValue, missing := resolve(contract.QueryField, args, nil)
	key, valid := keyValue.(string)
	if len(missing) != 0 || !valid || key == "" || len(key) > 256 ||
		(contract.FormatVersion == 1 && !invoiceKeyPattern.MatchString(key)) ||
		(contract.FormatVersion == 3 && !quickBooksKeyPattern.MatchString(key)) {
		return output
	}
	keyDigest := sha256.Sum256([]byte(key))
	output.summary.LookupKeySHA256 = hex.EncodeToString(keyDigest[:])
	var match *FactResolution
	for index := range resolutions {
		if resolutions[index].SourceVersionID != rail.SourceContextVersionID {
			continue
		}
		if match != nil {
			output.status, output.summary.Status = "untrusted", "untrusted"
			return output
		}
		match = &resolutions[index]
	}
	if match == nil {
		return output
	}
	if !match.AuthenticatedExecutor || match.Lookup != contract.Lookup || match.LookupKey != key ||
		match.ProviderAccountID != contract.ProviderAccountID ||
		match.SourceIdentity != contract.SourceIdentity ||
		match.AccountBoundary != contract.AccountBoundary ||
		((contract.FormatVersion == 1 || contract.FormatVersion == 3) && contract.ProviderAccountID == "") ||
		(contract.FormatVersion == 4 && (contract.SourceIdentity == "" || contract.AccountBoundary == "")) ||
		(contract.FormatVersion != 1 && contract.FormatVersion != 3 && contract.FormatVersion != 4) {
		output.status, output.summary.Status = "untrusted", "untrusted"
		return output
	}
	if match.Status == "unavailable" {
		return output
	}
	if match.Status != "ok" || match.Value == nil || match.ObservedAt == "" {
		output.status, output.summary.Status = "untrusted", "untrusted"
		return output
	}
	var value any
	switch contract.FormatVersion {
	case 1:
		value = match.Value["status"]
		status, ok := value.(string)
		if !ok || (status != "draft" && status != "open" && status != "paid" &&
			status != "uncollectible" && status != "void") {
			output.status, output.summary.Status = "untrusted", "untrusted"
			return output
		}
	case 3:
		value, _ = resolve(field{Root: "arguments", Path: []string{"Invoice", "Balance"}}, match.Value, nil)
		if !validFactValue(value, "number") {
			output.status, output.summary.Status = "untrusted", "untrusted"
			return output
		}
	case 4:
		value, _ = resolve(field{Root: "arguments", Path: contract.ResultPath}, match.Value, nil)
		if !validFactValue(value, contract.ValueType) {
			output.status, output.summary.Status = "untrusted", "untrusted"
			return output
		}
	}
	if number, ok := value.(json.Number); ok {
		value, _ = strconv.ParseFloat(string(number), 64)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, match.ObservedAt)
	if err != nil || observedAt.After(now.Add(5*time.Second)) {
		output.status, output.summary.Status = "untrusted", "untrusted"
		return output
	}
	output.summary.ObservedAt = match.ObservedAt
	age := now.Sub(observedAt).Seconds()
	if age < 0 {
		age = 0
	}
	output.summary.AgeSeconds = age
	if age > float64(contract.MaxAgeSeconds) {
		output.status, output.summary.Status = "stale", "stale"
		return output
	}
	output.value = value
	output.status, output.summary.Status = "trusted", "trusted"
	return output
}

func validFactValue(value any, kind string) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		if encoded, ok := value.(json.Number); ok {
			parsed, err := strconv.ParseFloat(string(encoded), 64)
			return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
		}
		number, ok := value.(float64)
		return ok && !math.IsNaN(number) && !math.IsInf(number, 0)
	case "boolean":
		_, ok := value.(bool)
		return ok
	default:
		return false
	}
}
