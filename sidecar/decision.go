package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Evaluation is advisory in Observe. It never authorizes execution.
type EvaluationRequest struct {
	FormatVersion      int                 `json:"formatVersion"`
	RequestID          string              `json:"requestId"`
	OperationVersionID string              `json:"operationVersionId"`
	Phase              string              `json:"phase"`
	Arguments          json.RawMessage     `json:"arguments"`
	Result             json.RawMessage     `json:"result,omitempty"`
	FactResolutions    []FactResolution    `json:"factResolutions,omitempty"`
	Trajectory         *TrajectorySnapshot `json:"trajectory,omitempty"`
	Attribution        Attribution         `json:"attribution"`
	IdentityProof      IdentityProof       `json:"identityProof"`
	ReviewSummary      *ReviewSummary      `json:"reviewSummary,omitempty"`
}

type Attribution struct {
	PrincipalID     string  `json:"principalId"`
	SessionID       string  `json:"sessionId"`
	ResourceID      *string `json:"resourceId"`
	PrincipalSource string  `json:"principalSource,omitempty"`
	ResourceSource  string  `json:"resourceSource,omitempty"`
}

type Evaluation struct {
	RequestID         string            `json:"requestId"`
	Mode              string            `json:"mode"`
	Enforced          bool              `json:"enforced"`
	Coverage          string            `json:"coverage"`
	Outcome           string            `json:"outcome"`
	Sequence          int64             `json:"sequence"`
	BundleID          *string           `json:"bundleId"`
	RailVersionIDs    []string          `json:"railVersionIds"`
	MatchedRuleIDs    []string          `json:"matchedRuleIds"`
	ReasonCodes       []string          `json:"reasonCodes"`
	Unresolved        []UnresolvedField `json:"unresolved"`
	Facts             []FactSummary     `json:"facts,omitempty"`
	RecordingStatus   string            `json:"recordingStatus,omitempty"`
	ReportReplayed    *bool             `json:"reportReplayed,omitempty"`
	ActionID          string            `json:"actionId,omitempty"`
	ApprovalRequestID *string           `json:"approvalRequestId,omitempty"`
	CertificateID     string            `json:"certificateId,omitempty"`
	readResult        bool              `json:"-"`
	readCall          bool              `json:"-"`
}

type UnresolvedField struct {
	Root   string   `json:"root"`
	Path   []string `json:"path"`
	Reason string   `json:"reason"`
}

type railBinding struct {
	RailID                 string       `json:"railId"`
	VersionID              string       `json:"versionId"`
	OperationVersionID     string       `json:"operationVersionId"`
	Kind                   string       `json:"kind"`
	SourceContextVersionID string       `json:"sourceContextVersionId"`
	SourceContextContract  factContract `json:"sourceContextContract"`
	OperationContract      struct {
		RequiredCoverage []string         `json:"requiredCoverage"`
		AvailableFields  []availableField `json:"availableFields"`
		ExpectedEffects  []struct {
			Kind string `json:"kind"`
		} `json:"expectedEffects"`
		ResourceIdentity *struct {
			Type  string   `json:"type"`
			Field []string `json:"field"`
		} `json:"resourceIdentity"`
	} `json:"operationContract"`
	Content struct {
		Rules        []json.RawMessage `json:"rules"`
		FactBindings []struct {
			FactKey           string `json:"factKey"`
			DataRailVersionID string `json:"dataRailVersionId"`
		} `json:"factBindings"`
	} `json:"content"`
}

type availableField struct {
	Root string   `json:"root"`
	Path []string `json:"path"`
	Type string   `json:"type"`
}

type decisionRule struct {
	ID                       string          `json:"id"`
	Kind                     string          `json:"kind"`
	Phase                    string          `json:"phase"`
	When                     json.RawMessage `json:"when"`
	Outcome                  string          `json:"outcome"`
	SourceOperationVersionID string          `json:"sourceOperationVersionId"`
}

type condition struct {
	Kind       string            `json:"kind"`
	Conditions []json.RawMessage `json:"conditions"`
	Condition  json.RawMessage   `json:"condition"`
	Left       field             `json:"left"`
	Comparison string            `json:"comparison"`
	Right      operand           `json:"right"`
}

type field struct {
	Root string   `json:"root"`
	Path []string `json:"path"`
}

type operand struct {
	Kind  string          `json:"kind"`
	Field field           `json:"field"`
	Value json.RawMessage `json:"value"`
}

type ruleResult struct {
	outcome    string
	matched    []string
	unresolved []UnresolvedField
}

func (s *Synchronizer) Evaluate(request EvaluationRequest) (Evaluation, error) {
	if request.FormatVersion != 1 || !uuidPattern.MatchString(request.RequestID) ||
		!uuidPattern.MatchString(request.OperationVersionID) ||
		(request.Phase != "tool_call" && request.Phase != "tool_result") ||
		len(request.FactResolutions) > 100 {
		return Evaluation{}, errors.New("evaluation request is invalid")
	}
	for _, resolution := range request.FactResolutions {
		value, err := json.Marshal(resolution.Value)
		if err != nil || len(value) > 16*1024 || len(resolution.LookupKey) > 256 {
			return Evaluation{}, errors.New("fact resolution is invalid")
		}
	}
	if !validTrajectory(request.Trajectory, request.Attribution.SessionID) {
		return Evaluation{}, errors.New("trajectory snapshot is invalid")
	}
	arguments, err := object(request.Arguments)
	if err != nil {
		return Evaluation{}, errors.New("arguments must be a JSON object")
	}
	var result map[string]any
	if request.Phase == "tool_result" {
		result, err = object(request.Result)
		if err != nil {
			return Evaluation{}, errors.New("result must be a JSON object")
		}
	} else if len(request.Result) > 0 {
		return Evaluation{}, errors.New("tool calls cannot include a result")
	}
	s.mu.RLock()
	current := s.state.Current
	floor := s.state.Floor
	s.mu.RUnlock()
	response := Evaluation{RequestID: request.RequestID, Mode: "observe", Enforced: false,
		Coverage: "unavailable", Outcome: "indeterminate", Sequence: floor,
		RailVersionIDs: []string{}, MatchedRuleIDs: []string{},
		ReasonCodes: []string{"bundle_unavailable"}, Unresolved: []UnresolvedField{}}
	if current == nil || current.Bundle == nil {
		return response, nil
	}
	manifest, err := verifyConfiguration(*current, s.options.OrganisationID,
		s.options.DeploymentID, s.options.TrustedPins, s.options.Now())
	if err != nil || manifest == nil || manifest.Sequence < floor {
		return response, nil
	}
	response.Mode = manifest.Mode
	response.BundleID = &manifest.BundleID
	response.Sequence = manifest.Sequence
	response.Coverage = "uncovered"
	response.ReasonCodes = []string{"operation_uncovered"}
	identityMissing := request.Attribution.PrincipalSource != "application_session" &&
		request.Attribution.PrincipalSource != "service_identity"
	var policyFound, denied, contextMissing, approval, policyAllowed bool
	selected := make([]railBinding, 0, len(manifest.Rails))
	coveredReads := make(map[string]bool)
	for _, raw := range manifest.Rails {
		var rail railBinding
		if err := json.Unmarshal(raw, &rail); err != nil || !uuidPattern.MatchString(rail.VersionID) ||
			!uuidPattern.MatchString(rail.OperationVersionID) {
			return invalidBundle(response), nil
		}
		if contains(rail.OperationContract.RequiredCoverage, "tool_result") {
			for _, effect := range rail.OperationContract.ExpectedEffects {
				if effect.Kind == "read" {
					coveredReads[rail.OperationVersionID] = true
				}
			}
		}
		if !strings.EqualFold(rail.OperationVersionID, request.OperationVersionID) {
			continue
		}
		if !contains(rail.OperationContract.RequiredCoverage, request.Phase) {
			continue
		}
		response.Coverage = "evaluated"
		response.RailVersionIDs = append(response.RailVersionIDs, rail.VersionID)
		selected = append(selected, rail)
		if rail.OperationContract.ResourceIdentity == nil {
			if request.Attribution.ResourceID != nil || request.Attribution.ResourceSource != "not_applicable" {
				identityMissing = true
			}
		} else {
			resource := rail.OperationContract.ResourceIdentity
			value, unresolved := resolve(field{Root: "arguments", Path: resource.Field}, arguments, result)
			resourceID, valid := value.(string)
			if len(unresolved) > 0 || request.Attribution.ResourceSource != "application_lookup" ||
				request.Attribution.ResourceID == nil || !valid || resourceID != *request.Attribution.ResourceID {
				identityMissing = true
			}
		}
	}
	if response.Coverage == "evaluated" && coveredReads[request.OperationVersionID] {
		response.readCall = request.Phase == "tool_call"
		response.readResult = request.Phase == "tool_result"
	}
	resolved := make(map[string]resolvedFact)
	for _, rail := range selected {
		if request.Trajectory != nil && !reviewedTrajectoryValues(request.Trajectory.Values, rail.OperationContract.AvailableFields) {
			return Evaluation{}, errors.New("trajectory fields are outside the reviewed Operation")
		}
		if rail.Kind != "data" {
			continue
		}
		fact := resolveDataFact(rail, arguments, request.FactResolutions, s.options.Now())
		resolved[rail.VersionID] = fact
		response.Facts = append(response.Facts, fact.summary)
	}
	for _, rail := range selected {
		if rail.Kind == "data" {
			continue
		}
		if rail.Kind != "guard" && rail.Kind != "policy" {
			return invalidBundle(response), nil
		}
		if rail.Kind == "policy" {
			policyFound = true
		}
		facts := make(map[string]resolvedFact)
		if rail.Kind == "policy" {
			for _, binding := range rail.Content.FactBindings {
				fact, exists := resolved[binding.DataRailVersionID]
				if exists && fact.summary.FactKey == binding.FactKey {
					facts[binding.FactKey] = fact
				}
			}
		}
		evaluated, err := evaluateRules(rail, request.Phase, arguments, result, request.Attribution, facts, request.Trajectory, coveredReads)
		if err != nil {
			return invalidBundle(response), nil
		}
		response.MatchedRuleIDs = append(response.MatchedRuleIDs, evaluated.matched...)
		response.Unresolved = append(response.Unresolved, evaluated.unresolved...)
		switch evaluated.outcome {
		case "deny":
			denied = true
		case "additional_context_required":
			contextMissing = true
		case "approval_required":
			approval = true
		case "allow":
			if rail.Kind == "policy" {
				policyAllowed = true
			}
		}
	}
	if response.Coverage != "evaluated" {
		return response, nil
	}
	if identityMissing {
		response.Coverage = "unavailable"
		response.Outcome = "additional_context_required"
		response.ReasonCodes = []string{"identity_unverified"}
		response.Unresolved = []UnresolvedField{{Root: "principal", Path: []string{"id"}, Reason: "unavailable"},
			{Root: "resource", Path: []string{"id"}, Reason: "unavailable"}}
		return response, nil
	}
	switch {
	case denied:
		response.Outcome = "deny"
		response.ReasonCodes = []string{"rail_denied"}
		response.Unresolved = []UnresolvedField{}
	case contextMissing:
		response.Outcome = "additional_context_required"
		response.ReasonCodes = []string{"trusted_context_missing"}
	case approval:
		response.Outcome = "approval_required"
		response.ReasonCodes = []string{"approval_required"}
	case policyFound && policyAllowed:
		response.Outcome = "allow"
		response.ReasonCodes = []string{"policy_allowed"}
	case policyFound:
		response.ReasonCodes = []string{"no_rule_matched"}
	default:
		response.ReasonCodes = []string{"no_policy_authority"}
	}
	return response, nil
}

func invalidBundle(value Evaluation) Evaluation {
	value.Coverage = "unavailable"
	value.Outcome = "indeterminate"
	value.RailVersionIDs = []string{}
	value.MatchedRuleIDs = []string{}
	value.ReasonCodes = []string{"bundle_unavailable"}
	value.Unresolved = []UnresolvedField{}
	value.Facts = nil
	return value
}

func evaluateRules(rail railBinding, phase string, args, result map[string]any,
	attribution Attribution, facts map[string]resolvedFact, trajectory *TrajectorySnapshot,
	coveredReads map[string]bool) (ruleResult, error) {
	if len(rail.Content.Rules) == 0 {
		return ruleResult{}, errors.New("rules are missing")
	}
	output := ruleResult{outcome: "indeterminate"}
	var denied, missing, approval, allowed bool
	for _, raw := range rail.Content.Rules {
		var rule decisionRule
		if err := json.Unmarshal(raw, &rule); err != nil || rule.ID == "" {
			return output, errors.New("rule is invalid")
		}
		if rail.Kind == "guard" && rule.Phase != phase {
			continue
		}
		if rail.Kind == "guard" && rule.Kind == "prior_read" {
			if rule.Outcome != "deny" || !uuidPattern.MatchString(rule.SourceOperationVersionID) ||
				rule.SourceOperationVersionID != strings.ToLower(rule.SourceOperationVersionID) {
				return output, errors.New("prior read rule is invalid")
			}
			if !coveredReads[rule.SourceOperationVersionID] {
				missing = true
				output.unresolved = append(output.unresolved, UnresolvedField{Root: "trajectory",
					Path: []string{"priorReadOperationVersionIds"}, Reason: "unavailable"})
			} else if trajectory == nil || !trajectory.Complete || !trajectory.verified {
				missing = true
				output.unresolved = append(output.unresolved, UnresolvedField{Root: "trajectory",
					Path: []string{"priorReadOperationVersionIds"}, Reason: "missing"})
			} else if contains(trajectory.PriorReadOperationVersionIDs, rule.SourceOperationVersionID) {
				denied = true
				output.matched = append(output.matched, rule.ID)
			}
			continue
		}
		matched, unresolved, err := evaluateCondition(rule.When, args, result, attribution, facts, trajectory, 0)
		if err != nil {
			return output, err
		}
		output.unresolved = append(output.unresolved, unresolved...)
		if len(unresolved) > 0 {
			missing = true
		}
		if !matched {
			continue
		}
		output.matched = append(output.matched, rule.ID)
		switch rule.Outcome {
		case "deny":
			denied = true
		case "approval_required":
			if rail.Kind != "policy" {
				return output, errors.New("guard cannot require approval")
			}
			approval = true
		case "allow":
			allowed = true
		default:
			return output, errors.New("rule outcome is invalid")
		}
	}
	switch {
	case denied:
		output.outcome = "deny"
		output.unresolved = nil
	case missing:
		output.outcome = "additional_context_required"
	case approval:
		output.outcome = "approval_required"
	case allowed:
		output.outcome = "allow"
	}
	return output, nil
}

func evaluateCondition(raw json.RawMessage, args, result map[string]any, attribution Attribution,
	facts map[string]resolvedFact, trajectory *TrajectorySnapshot, depth int) (bool, []UnresolvedField, error) {
	if depth > 8 {
		return false, nil, errors.New("condition is too deep")
	}
	var node condition
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, nil, err
	}
	switch node.Kind {
	case "all", "any":
		if len(node.Conditions) == 0 || len(node.Conditions) > 16 {
			return false, nil, errors.New("condition is invalid")
		}
		anyTrue, anyFalse := false, false
		var unresolved []UnresolvedField
		for _, child := range node.Conditions {
			matched, missing, err := evaluateCondition(child, args, result, attribution, facts, trajectory, depth+1)
			if err != nil {
				return false, nil, err
			}
			if len(missing) > 0 {
				unresolved = append(unresolved, missing...)
			} else if matched {
				anyTrue = true
			} else {
				anyFalse = true
			}
		}
		if node.Kind == "all" {
			if anyFalse {
				return false, nil, nil
			}
			if len(unresolved) > 0 {
				return false, unresolved, nil
			}
			return true, nil, nil
		}
		if anyTrue {
			return true, nil, nil
		}
		if len(unresolved) > 0 {
			return false, unresolved, nil
		}
		return false, nil, nil
	case "not":
		matched, unresolved, err := evaluateCondition(node.Condition, args, result, attribution, facts, trajectory, depth+1)
		if err != nil || len(unresolved) > 0 {
			return false, unresolved, err
		}
		return !matched, nil, nil
	case "compare":
		left, leftMissing := resolveIdentity(node.Left, args, result, attribution, facts, trajectory)
		var right any
		var rightMissing []UnresolvedField
		if node.Right.Kind == "field" {
			right, rightMissing = resolveIdentity(node.Right.Field, args, result, attribution, facts, trajectory)
		} else if node.Right.Kind == "literal" {
			if err := json.Unmarshal(node.Right.Value, &right); err != nil {
				return false, nil, err
			}
		} else {
			return false, nil, errors.New("operand is invalid")
		}
		missing := append(leftMissing, rightMissing...)
		if len(missing) > 0 {
			return false, missing, nil
		}
		if left == nil || right == nil {
			if node.Comparison == "eq" {
				return left == nil && right == nil, nil, nil
			}
			if node.Comparison == "neq" {
				return (left == nil) != (right == nil), nil, nil
			}
			return false, []UnresolvedField{{Root: node.Left.Root, Path: node.Left.Path, Reason: "invalid_type"}}, nil
		}
		switch l := left.(type) {
		case float64:
			r, ok := right.(float64)
			if !ok {
				break
			}
			switch node.Comparison {
			case "eq":
				return l == r, nil, nil
			case "neq":
				return l != r, nil, nil
			case "gt":
				return l > r, nil, nil
			case "gte":
				return l >= r, nil, nil
			case "lt":
				return l < r, nil, nil
			case "lte":
				return l <= r, nil, nil
			}
		case string:
			r, ok := right.(string)
			if !ok {
				break
			}
			if node.Comparison == "eq" {
				return l == r, nil, nil
			}
			if node.Comparison == "neq" {
				return l != r, nil, nil
			}
		case bool:
			r, ok := right.(bool)
			if !ok {
				break
			}
			if node.Comparison == "eq" {
				return l == r, nil, nil
			}
			if node.Comparison == "neq" {
				return l != r, nil, nil
			}
		}
		return false, []UnresolvedField{{Root: node.Left.Root, Path: node.Left.Path, Reason: "invalid_type"}}, nil
	default:
		return false, nil, errors.New("condition kind is invalid")
	}
}

func resolve(f field, args, result map[string]any) (any, []UnresolvedField) {
	if len(f.Path) == 0 || len(f.Path) > 12 {
		return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "invalid_type"}}
	}
	var value any
	switch f.Root {
	case "arguments":
		value = args
	case "result":
		value = result
	case "facts":
		return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "unavailable"}}
	default:
		return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "missing"}}
	}
	for _, part := range f.Path {
		if part == "" || part == "__proto__" || part == "constructor" || part == "prototype" {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "invalid_type"}}
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "missing"}}
		}
		next, exists := object[part]
		if !exists {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "missing"}}
		}
		value = next
	}
	return value, nil
}

func resolveIdentity(f field, args, result map[string]any, attribution Attribution,
	facts map[string]resolvedFact, trajectory *TrajectorySnapshot) (any, []UnresolvedField) {
	if f.Root == "trajectory" && len(f.Path) == 1 && f.Path[0] == "priorReadOperationVersionIds" {
		if trajectory == nil || !trajectory.Complete || !trajectory.verified {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "missing"}}
		}
		return trajectory.PriorReadOperationVersionIDs, nil
	}
	if f.Root == "trajectory" {
		if trajectory == nil || !trajectory.Complete || !trajectory.verified {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "missing"}}
		}
		value, unresolved := resolve(field{Root: "arguments", Path: f.Path}, trajectory.Values, nil)
		if len(unresolved) != 0 {
			return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: unresolved[0].Reason}}
		}
		if number, ok := value.(json.Number); ok {
			parsed, err := number.Float64()
			if err != nil {
				return nil, []UnresolvedField{{Root: f.Root, Path: f.Path, Reason: "invalid_type"}}
			}
			return parsed, nil
		}
		return value, nil
	}
	if f.Root == "facts" && len(f.Path) == 1 {
		fact, found := facts[f.Path[0]]
		if found && fact.status == "trusted" {
			return fact.value, nil
		}
		reason := "unavailable"
		if found {
			reason = fact.status
		}
		return nil, []UnresolvedField{{Root: "facts", Path: f.Path, Reason: reason}}
	}
	if len(f.Path) == 1 && f.Path[0] == "id" {
		switch f.Root {
		case "principal":
			return attribution.PrincipalID, nil
		case "resource":
			if attribution.ResourceID != nil {
				return *attribution.ResourceID, nil
			}
		}
	}
	return resolve(f, args, result)
}

func object(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, errors.New("object size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, errors.New("object is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("object has trailing data")
	}
	return value, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
