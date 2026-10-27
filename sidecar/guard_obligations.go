package sidecar

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Targets and evidence keys are declared in canonical UTF-8 order for SDK proofs.
type GuardTarget struct {
	Path []string `json:"path"`
	Root string   `json:"root"`
}

type GuardObligation struct {
	Kind           string      `json:"kind"`
	HandlerID      string      `json:"handlerId"`
	HandlerVersion string      `json:"handlerVersion"`
	Target         GuardTarget `json:"target"`
}

// Reject unknown declaration fields so a signed bundle cannot silently lose semantics.
func (item *GuardObligation) UnmarshalJSON(data []byte) error {
	type declaration GuardObligation
	var value declaration
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*item = GuardObligation(value)
	return nil
}

type GuardEvidence struct {
	BundleID       string      `json:"bundleId"`
	HandlerID      string      `json:"handlerId"`
	HandlerVersion string      `json:"handlerVersion"`
	InputSHA256    string      `json:"inputSha256"`
	Kind           string      `json:"kind"`
	OutputSHA256   string      `json:"outputSha256"`
	Phase          string      `json:"phase"`
	Target         GuardTarget `json:"target"`
}

type GuardRequirement struct {
	RailVersionID string `json:"railVersionId"`
	RuleID        string `json:"ruleId"`
	GuardObligation
}

type GuardObligationStatus struct {
	GuardRequirement
	Status       string `json:"status"`
	InputSHA256  string `json:"inputSha256,omitempty"`
	OutputSHA256 string `json:"outputSha256,omitempty"`
}

type GuardPlan struct {
	FormatVersion      int                `json:"formatVersion"`
	OperationVersionID string             `json:"operationVersionId"`
	Phase              string             `json:"phase"`
	BundleID           *string            `json:"bundleId"`
	Sequence           int64              `json:"sequence"`
	Coverage           string             `json:"coverage"`
	Requirements       []GuardRequirement `json:"requirements"`
}

var guardID = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,79}$`)
var guardSegment = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
var guardDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validGuardObligation(item GuardObligation, phase string) bool {
	root := "arguments"
	if phase == "tool_result" {
		root = "result"
	}
	if (item.Kind != "sanitize" && item.Kind != "transform" && item.Kind != "isolate") ||
		!guardID.MatchString(item.HandlerID) || !guardDigest.MatchString(item.HandlerVersion) ||
		item.Target.Root != root || len(item.Target.Path) < 1 || len(item.Target.Path) > 8 {
		return false
	}
	for _, part := range item.Target.Path {
		if !guardSegment.MatchString(part) || part == "__proto__" || part == "prototype" || part == "constructor" {
			return false
		}
	}
	return true
}

func sameGuardTarget(left, right GuardTarget) bool {
	if left.Root != right.Root || len(left.Path) != len(right.Path) {
		return false
	}
	for index := range left.Path {
		if left.Path[index] != right.Path[index] {
			return false
		}
	}
	return true
}

func sameGuardObligation(left, right GuardObligation) bool {
	return left.Kind == right.Kind && left.HandlerID == right.HandlerID &&
		left.HandlerVersion == right.HandlerVersion && sameGuardTarget(left.Target, right.Target)
}

func guardTargetsOverlap(left, right GuardTarget) bool {
	if left.Root != right.Root {
		return false
	}
	for index := 0; index < len(left.Path) && index < len(right.Path); index++ {
		if left.Path[index] != right.Path[index] {
			return false
		}
	}
	return true
}

func collectGuardRequirements(rails []railBinding, phase string) ([]GuardRequirement, error) {
	items := []GuardRequirement{}
	for _, rail := range rails {
		if rail.Kind != "guard" {
			continue
		}
		for _, raw := range rail.Content.Rules {
			var rule decisionRule
			if json.Unmarshal(raw, &rule) != nil {
				return nil, errors.New("invalid Guard rule")
			}
			if rule.Phase != phase {
				continue
			}
			if (len(rule.Obligations) > 0 && rail.Content.FormatVersion != 3) || len(rule.Obligations) > 8 || (len(rule.Obligations) > 0 && !guardID.MatchString(rule.ID)) {
				return nil, errors.New("invalid Guard requirements")
			}
			for _, item := range rule.Obligations {
				if !validGuardObligation(item, phase) {
					return nil, errors.New("invalid Guard requirement")
				}
				// Even a signed bundle cannot claim an unreviewed field or change the target identity.
				reviewed := false
				for _, field := range rail.OperationContract.AvailableFields {
					if field.Type == "string" && sameGuardTarget(item.Target, GuardTarget{Root: field.Root, Path: field.Path}) {
						reviewed = true
					}
				}
				if !reviewed || (item.Target.Root == "arguments" && rail.OperationContract.ResourceIdentity != nil &&
					guardTargetsOverlap(item.Target, GuardTarget{Root: "arguments", Path: rail.OperationContract.ResourceIdentity.Field})) {
					return nil, errors.New("unreviewed Guard target")
				}
				items = append(items, GuardRequirement{rail.VersionID, rule.ID, item})
				if len(items) > 64 {
					return nil, errors.New("too many Guard requirements")
				}
			}
		}
	}
	return items, nil
}

func guardEvidenceObligation(proof GuardEvidence) GuardObligation {
	return GuardObligation{Kind: proof.Kind, HandlerID: proof.HandlerID, HandlerVersion: proof.HandlerVersion, Target: proof.Target}
}

func validGuardEvidence(items []GuardEvidence, phase string) bool {
	if len(items) > 128 {
		return false
	}
	for _, item := range items {
		if (item.Phase != "tool_call" && item.Phase != "tool_result") ||
			(phase == "tool_call" && item.Phase != "tool_call") ||
			!uuidPattern.MatchString(item.BundleID) || !guardDigest.MatchString(item.InputSHA256) ||
			!guardDigest.MatchString(item.OutputSHA256) || !validGuardObligation(guardEvidenceObligation(item), item.Phase) {
			return false
		}
	}
	return true
}

func evaluateGuardObligations(requirements []GuardRequirement, evidence []GuardEvidence,
	phase, bundleID string, arguments, result map[string]any) []GuardObligationStatus {
	statuses := make([]GuardObligationStatus, 0, len(requirements))
	for _, item := range requirements {
		status := GuardObligationStatus{GuardRequirement: item, Status: "missing"}
		for _, other := range requirements {
			if guardTargetsOverlap(item.Target, other.Target) && !sameGuardObligation(item.GuardObligation, other.GuardObligation) {
				status.Status = "conflict"
			}
		}
		var proof *GuardEvidence
		count := 0
		for index := range evidence {
			candidate := &evidence[index]
			if candidate.Phase == phase && candidate.BundleID == bundleID && sameGuardObligation(item.GuardObligation, guardEvidenceObligation(*candidate)) {
				proof = candidate
				count++
			}
		}
		value, unresolved := resolve(field{Root: item.Target.Root, Path: item.Target.Path}, arguments, result)
		text, isString := value.(string)
		if status.Status != "conflict" && item.Kind != "isolate" && count == 1 && isString && len(unresolved) == 0 {
			encoded, _ := json.Marshal(text)
			digest := sha256.Sum256(encoded)
			if proof.OutputSHA256 == hex.EncodeToString(digest[:]) {
				status.Status = "fulfilled"
				status.InputSHA256 = proof.InputSHA256
				status.OutputSHA256 = proof.OutputSHA256
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// GuardRequirementsHandler is a non-authorizing, side-effect-free read of the current signed bundle.
func GuardRequirementsHandler(syncer *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		value := r.Header.Get("Authorization")
		if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(value, "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(value, "Bearer ")), []byte(adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		query := r.URL.Query()
		operationID, phase := query.Get("operationVersionId"), query.Get("phase")
		if len(query) != 2 || len(query["operationVersionId"]) != 1 || len(query["phase"]) != 1 ||
			!uuidPattern.MatchString(operationID) || (phase != "tool_call" && phase != "tool_result") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plan := syncer.guardPlan(operationID, phase)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	})
}

func (s *Synchronizer) guardPlan(operationID, phase string) GuardPlan {
	plan := GuardPlan{FormatVersion: 1, OperationVersionID: operationID, Phase: phase,
		Coverage: "unavailable", Requirements: []GuardRequirement{}}
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
	plan.BundleID = &manifest.BundleID
	plan.Sequence = manifest.Sequence
	plan.Coverage = "uncovered"
	selected := []railBinding{}
	for _, raw := range manifest.Rails {
		var rail railBinding
		if json.Unmarshal(raw, &rail) != nil {
			plan.Coverage = "unavailable"
			return plan
		}
		if strings.EqualFold(rail.OperationVersionID, operationID) && contains(rail.OperationContract.RequiredCoverage, phase) {
			selected = append(selected, rail)
			plan.Coverage = "evaluated"
		}
	}
	items, err := collectGuardRequirements(selected, phase)
	if err != nil {
		plan.Coverage = "unavailable"
		return plan
	}
	plan.Requirements = items
	return plan
}
