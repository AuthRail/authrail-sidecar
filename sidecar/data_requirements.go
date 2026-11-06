package sidecar

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type dataRequirement struct {
	SourceVersionID string          `json:"sourceVersionId"`
	Contract        json.RawMessage `json:"contract"`
}

type dataPlan struct {
	FormatVersion      int               `json:"formatVersion"`
	OperationVersionID string            `json:"operationVersionId"`
	Phase              string            `json:"phase"`
	BundleID           *string           `json:"bundleId"`
	Sequence           int64             `json:"sequence"`
	Coverage           string            `json:"coverage"`
	Requirements       []dataRequirement `json:"requirements"`
}

// DataRequirementsHandler describes reviewed reads; it grants no provider access or business permission.
func DataRequirementsHandler(s *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		operationID, phase := query.Get("operationVersionId"), query.Get("phase")
		if len(query) != 2 || len(query["operationVersionId"]) != 1 || len(query["phase"]) != 1 || !uuidPattern.MatchString(operationID) || phase != "tool_call" && phase != "tool_result" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.dataPlan(operationID, phase))
	})
}

func (s *Synchronizer) dataPlan(operationID, phase string) dataPlan {
	plan := dataPlan{FormatVersion: 1, OperationVersionID: operationID, Phase: phase, Coverage: "unavailable", Requirements: []dataRequirement{}}
	s.mu.RLock()
	current, floor := s.state.Current, s.state.Floor
	s.mu.RUnlock()
	plan.Sequence = floor
	if current == nil || current.Bundle == nil {
		return plan
	}
	manifest, err := verifyConfiguration(*current, s.options.OrganisationID, s.options.DeploymentID, s.options.TrustedPins, s.options.Now())
	if err != nil || manifest == nil || manifest.Sequence < floor {
		return plan
	}
	plan.BundleID, plan.Sequence, plan.Coverage = &manifest.BundleID, manifest.Sequence, "uncovered"
	requirements := map[string]dataRequirement{}
	canonical := map[string][]byte{}
	unavailable := func() dataPlan { plan.Coverage = "unavailable"; plan.Requirements = []dataRequirement{}; return plan }
	for _, raw := range manifest.Rails {
		var rail railBinding
		if json.Unmarshal(raw, &rail) != nil {
			return unavailable()
		}
		if !strings.EqualFold(rail.OperationVersionID, operationID) || !contains(rail.OperationContract.RequiredCoverage, phase) {
			continue
		}
		plan.Coverage = "evaluated"
		if rail.Kind != "data" {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || !uuidPattern.MatchString(rail.SourceContextVersionID) {
			return unavailable()
		}
		contract := fields["sourceContextContract"]
		if !validDataPlanContract(contract) {
			return unavailable()
		}
		normalized, _ := json.Marshal(rail.SourceContextContract)
		if previous, exists := canonical[rail.SourceContextVersionID]; exists && !bytes.Equal(previous, normalized) {
			return unavailable()
		}
		canonical[rail.SourceContextVersionID] = normalized
		requirements[rail.SourceContextVersionID] = dataRequirement{SourceVersionID: rail.SourceContextVersionID, Contract: append(json.RawMessage(nil), contract...)}
		if len(requirements) > 32 {
			return unavailable()
		}
	}
	ids := make([]string, 0, len(requirements))
	for id := range requirements {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		plan.Requirements = append(plan.Requirements, requirements[id])
	}
	return plan
}

var dataSourceIdentity = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{2,159}$`)
var dataAccountBoundary = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$`)
var dataFactKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
var dataStripeAccount = regexp.MustCompile(`^acct_[A-Za-z0-9]{8,80}$`)
var dataQuickBooksAccount = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var dataModelID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{1,159}$`)
var dataPromptVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{1,159}$`)

// Validate the distributed descriptor without inventing a reader for a legacy or unknown shape.
func validDataPlanContract(raw json.RawMessage) bool {
	var contract factContract
	if json.Unmarshal(raw, &contract) != nil || contract.QueryField.Root != "arguments" || !validDataQueryPath(contract.QueryField.Path) || !dataFactKey.MatchString(contract.FactKey) || contract.Lookup == "" || contract.MaxAgeSeconds < 1 || contract.MaxAgeSeconds > 3600 || contract.TimeoutMs < 100 || contract.TimeoutMs > 10000 || contract.Failure != "unavailable" {
		return false
	}
	keys := []string{"formatVersion", "provider", "lookup", "providerAccountId", "queryField", "factKey", "resultField", "maxAgeSeconds", "timeoutMs", "failure"}
	switch contract.FormatVersion {
	case 1:
		if contract.Provider != "stripe" || contract.Lookup != "invoice.retrieve" || contract.ResultField != "status" || !dataStripeAccount.MatchString(contract.ProviderAccountID) {
			return false
		}
	case 3:
		if contract.Provider != "quickbooks" || contract.Lookup != "invoice.read" || contract.ResultField != "Balance" || !dataQuickBooksAccount.MatchString(contract.ProviderAccountID) {
			return false
		}
	case 4, 5:
		keys = []string{"formatVersion", "kind", "sourceIdentity", "accountBoundary", "lookup", "queryField", "factKey", "resultPath", "valueType", "maxAgeSeconds", "timeoutMs", "failure"}
		if !dataSourceIdentity.MatchString(contract.SourceIdentity) || !dataAccountBoundary.MatchString(contract.AccountBoundary) || !dataSourceIdentity.MatchString(contract.Lookup) || !validDataPath(contract.ResultPath, 8) || !contains([]string{"string", "number", "boolean"}, contract.ValueType) {
			return false
		}
		if contract.FormatVersion == 4 && !contains([]string{"customer_api", "database", "mcp", "sdk"}, contract.Kind) {
			return false
		}
		if contract.FormatVersion == 5 {
			keys = append(keys, "modelId", "modelConfigSha256", "promptVersion", "maxInputBytes", "maxOutputBytes")
			if contract.Kind != "extraction" || !dataModelID.MatchString(contract.ModelID) || !extractionDigestPattern.MatchString(contract.ModelConfigSHA256) || !dataPromptVersion.MatchString(contract.PromptVersion) || contract.MaxInputBytes < 1 || contract.MaxInputBytes > 65536 || contract.MaxOutputBytes < 1 || contract.MaxOutputBytes > 4096 {
				return false
			}
		}
	default:
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := fields[key]; !exists {
			return false
		}
	}
	var query map[string]json.RawMessage
	if json.Unmarshal(fields["queryField"], &query) != nil || len(query) != 2 || query["root"] == nil || query["path"] == nil {
		return false
	}
	return true
}

func validDataPath(path []string, maximum int) bool {
	if len(path) < 1 || len(path) > maximum {
		return false
	}
	for _, part := range path {
		if !guardSegment.MatchString(part) || part == "__proto__" || part == "prototype" || part == "constructor" {
			return false
		}
	}
	return true
}

func validDataQueryPath(path []string) bool {
	if len(path) < 1 || len(path) > 12 {
		return false
	}
	for _, part := range path {
		if !utf8.ValidString(part) || len([]rune(part)) < 1 || len([]rune(part)) > 80 || part == "__proto__" || part == "prototype" || part == "constructor" {
			return false
		}
		for _, char := range part {
			if char < 32 {
				return false
			}
		}
	}
	return true
}
