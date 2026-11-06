package sidecar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type contextualAnswer struct {
	Type    string   `json:"type"`
	Choices []string `json:"choices,omitempty"`
	Minimum float64  `json:"minimum,omitempty"`
	Maximum float64  `json:"maximum,omitempty"`
}
type contextualAssessment struct {
	ID       string           `json:"id"`
	Phase    string           `json:"phase"`
	Question string           `json:"question"`
	Fields   []field          `json:"fields"`
	Answer   contextualAnswer `json:"answer"`
}
type contextualConfiguration struct {
	Enabled     bool                   `json:"enabled"`
	Assessments []contextualAssessment `json:"assessments"`
}

// ContextualFinding contains AuthRail's signed interpretation, never the selected source text.
type ContextualFinding struct {
	Payload   string `json:"payload"`
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}
type contextualValue struct {
	Type               string    `json:"type"`
	OrganisationID     string    `json:"organisationId"`
	DeploymentID       string    `json:"deploymentId"`
	BundleID           string    `json:"bundleId"`
	RailVersionID      string    `json:"railVersionId"`
	AssessmentID       string    `json:"assessmentId"`
	OperationVersionID string    `json:"operationVersionId"`
	RequestID          string    `json:"requestId"`
	Phase              string    `json:"phase"`
	InputSHA256        string    `json:"inputSha256"`
	AttributionSHA256  string    `json:"attributionSha256"`
	MaterialSHA256     string    `json:"materialSha256"`
	Status             string    `json:"status"`
	Value              any       `json:"value,omitempty"`
	IssuedAt           time.Time `json:"issuedAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
}
type ContextualSummary struct {
	RailVersionID string             `json:"railVersionId"`
	AssessmentID  string             `json:"assessmentId"`
	Status        string             `json:"status"`
	Finding       *ContextualFinding `json:"finding,omitempty"`
}
type contextualRequirement struct {
	RailVersionID string               `json:"railVersionId"`
	Assessment    contextualAssessment `json:"assessment"`
}
type contextualPlan struct {
	FormatVersion          int                     `json:"formatVersion"`
	OperationVersionID     string                  `json:"operationVersionId"`
	Phase                  string                  `json:"phase"`
	BundleID               *string                 `json:"bundleId"`
	Sequence               int64                   `json:"sequence"`
	Coverage               string                  `json:"coverage"`
	Requirements           []contextualRequirement `json:"requirements"`
	DisclosureProcessing   bool                    `json:"disclosureProcessing"`
	DisclosureRequirements []GuardRequirement      `json:"disclosureRequirements"`
	credentialFields       []field
}
type contextualRequest struct {
	FormatVersion      int           `json:"formatVersion"`
	BundleID           string        `json:"bundleId"`
	RailVersionID      string        `json:"railVersionId"`
	AssessmentID       string        `json:"assessmentId"`
	OperationVersionID string        `json:"operationVersionId"`
	RequestID          string        `json:"requestId"`
	Phase              string        `json:"phase"`
	InputSHA256        string        `json:"inputSha256"`
	AttributionSHA256  string        `json:"attributionSha256"`
	Material           string        `json:"material"`
	KeySHA256          string        `json:"keySha256"`
	Proof              IdentityProof `json:"proof"`
}

func (s *Synchronizer) contextualPlan(operationID, phase string) contextualPlan {
	plan := contextualPlan{FormatVersion: 1, OperationVersionID: operationID, Phase: phase,
		Coverage: "unavailable", Requirements: []contextualRequirement{}, DisclosureRequirements: []GuardRequirement{}}
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
	for _, raw := range manifest.Rails {
		var rail railBinding
		if json.Unmarshal(raw, &rail) != nil {
			plan.Coverage = "unavailable"
			plan.Requirements = []contextualRequirement{}
			return plan
		}
		if rail.OperationVersionID != operationID || !contains(rail.OperationContract.RequiredCoverage, phase) {
			continue
		}
		plan.Coverage = "evaluated"
		if !rail.Content.Contextual.Enabled {
			continue
		}
		for _, assessment := range rail.Content.Contextual.Assessments {
			if assessment.Phase == phase || rail.Kind == "policy" && assessment.Phase == "tool_call" {
				plan.Requirements = append(plan.Requirements, contextualRequirement{rail.VersionID, assessment})
			}
		}
	}
	if len(plan.Requirements) > 8 {
		plan.Coverage = "unavailable"
		plan.Requirements = []contextualRequirement{}
	}
	phases := []string{phase}
	// A result-time assessment can reuse request material, which still requires its call-time processing.
	if phase == "tool_result" {
		for _, requirement := range plan.Requirements {
			for _, field := range requirement.Assessment.Fields {
				if field.Root == "arguments" {
					phases = []string{"tool_call", "tool_result"}
					break
				}
			}
			if len(phases) == 2 {
				break
			}
		}
	}
	for _, raw := range manifest.Rails {
		var rail railBinding
		if json.Unmarshal(raw, &rail) != nil || rail.OperationVersionID != operationID || rail.Kind != "guard" {
			continue
		}
		for _, selectedPhase := range phases {
			requirements, err := collectGuardRequirements([]railBinding{rail}, selectedPhase)
			if err != nil {
				plan.Coverage = "unavailable"
				plan.Requirements = []contextualRequirement{}
				return plan
			}
			credentialFields, err := credentialDisclosureFields(rail, selectedPhase)
			if err != nil {
				plan.Coverage = "unavailable"
				plan.Requirements = []contextualRequirement{}
				return plan
			}
			plan.credentialFields = append(plan.credentialFields, credentialFields...)
			if len(requirements) > 0 {
				plan.DisclosureProcessing = true
				plan.DisclosureRequirements = append(plan.DisclosureRequirements, requirements...)
			}
		}
	}
	if len(plan.DisclosureRequirements) > 128 {
		plan.Coverage = "unavailable"
		plan.Requirements = []contextualRequirement{}
	}
	return plan
}

// ContextualHandler serves only enabled signed requirements and authenticated reading requests.
func ContextualHandler(s *Synchronizer, adapterToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+adapterToken)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			q := r.URL.Query()
			op, phase := q.Get("operationVersionId"), q.Get("phase")
			if len(q) != 2 || len(q["operationVersionId"]) != 1 || len(q["phase"]) != 1 || !uuidPattern.MatchString(op) || phase != "tool_call" && phase != "tool_result" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.contextualPlan(op, phase))
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var request contextualRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !s.validContextualRequest(request) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		data, err := json.Marshal(request)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		forward, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.options.ControlPlaneURL, "/")+"/runtime/deployment/contextual-readings", bytes.NewReader(data))
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		forward.Header.Set("Authorization", "Bearer "+s.options.Token)
		forward.Header.Set("Content-Type", "application/json")
		if parent := r.Header.Get("traceparent"); validTraceparent(parent) {
			forward.Header.Set("traceparent", parent)
		}
		response, err := s.options.Client.Do(forward)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var finding ContextualFinding
		decoder = json.NewDecoder(io.LimitReader(response.Body, 8193))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&finding) != nil || decoder.Decode(new(any)) != io.EOF || len(finding.Payload) > 4096 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(finding)
	})
}

func (s *Synchronizer) validContextualRequest(request contextualRequest) bool {
	plan := s.contextualPlan(request.OperationVersionID, request.Phase)
	if request.FormatVersion != 1 || plan.Coverage != "evaluated" || plan.BundleID == nil || *plan.BundleID != request.BundleID ||
		!uuidPattern.MatchString(request.RequestID) || !extractionDigestPattern.MatchString(request.AttributionSHA256) || !extractionDigestPattern.MatchString(request.InputSHA256) || len(request.Material) > 24000 {
		return false
	}
	var selected *contextualAssessment
	for _, requirement := range plan.Requirements {
		if requirement.RailVersionID == request.RailVersionID && requirement.Assessment.ID == request.AssessmentID {
			item := requirement.Assessment
			selected = &item
		}
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(request.Material)
	if err != nil || len(material) > 16384 {
		return false
	}
	var fields []string
	if json.Unmarshal(material, &fields) != nil || selected == nil || len(fields) != len(selected.Fields) {
		return false
	}
	for index, value := range fields {
		if strings.TrimSpace(value) == "" {
			return false
		}
		selectedField := GuardTarget{Root: selected.Fields[index].Root, Path: selected.Fields[index].Path}
		protected := false
		for _, target := range plan.credentialFields {
			protected = protected || sameGuardTarget(selectedField, GuardTarget{Root: target.Root, Path: target.Path})
		}
		for _, requirement := range plan.DisclosureRequirements {
			protected = protected || requirement.HandlerID == credentialRedactionHandlerID && sameGuardTarget(selectedField, requirement.Target)
		}
		// Observe preserves business behaviour, but never authorizes a disclosure
		// that a selected local credential protection explicitly forbids.
		if protected && credentialFormatV1(value) {
			return false
		}
	}
	proof := request.Proof
	now := s.options.Now()
	if proof.IssuedAt <= 0 || proof.ExpiresAt <= proof.IssuedAt || proof.ExpiresAt-proof.IssuedAt > 60 ||
		time.Unix(proof.IssuedAt, 0).After(now.Add(5*time.Second)) || !time.Unix(proof.ExpiresAt, 0).After(now) {
		return false
	}
	hash := sha256.Sum256(material)
	statement, _ := json.Marshal(struct {
		Type               string `json:"type"`
		OrganisationID     string `json:"organisationId"`
		DeploymentID       string `json:"deploymentId"`
		BundleID           string `json:"bundleId"`
		RailVersionID      string `json:"railVersionId"`
		AssessmentID       string `json:"assessmentId"`
		OperationVersionID string `json:"operationVersionId"`
		RequestID          string `json:"requestId"`
		Phase              string `json:"phase"`
		InputSHA256        string `json:"inputSha256"`
		AttributionSHA256  string `json:"attributionSha256"`
		MaterialSHA256     string `json:"materialSha256"`
		KeySHA256          string `json:"keySha256"`
		IssuedAt           int64  `json:"issuedAt"`
		ExpiresAt          int64  `json:"expiresAt"`
	}{"authrail.contextual.request.v1", s.options.OrganisationID, s.options.DeploymentID, request.BundleID, request.RailVersionID, request.AssessmentID,
		request.OperationVersionID, request.RequestID, request.Phase, request.InputSHA256, request.AttributionSHA256, hex.EncodeToString(hash[:]), request.KeySHA256, proof.IssuedAt, proof.ExpiresAt})
	signature, err := base64.RawURLEncoding.Strict().DecodeString(proof.Signature)
	if err != nil {
		return false
	}
	for _, key := range s.options.ExecutorPublicKeys {
		digest := sha256.Sum256(key)
		if hex.EncodeToString(digest[:]) == request.KeySHA256 && ed25519.Verify(key, statement, signature) {
			return true
		}
	}
	return false
}

func (s *Synchronizer) resolveContextual(rail railBinding, assessment contextualAssessment, request EvaluationRequest,
	args, result map[string]any, current *Configuration, manifest *Manifest) (resolvedFact, ContextualSummary) {
	summary := ContextualSummary{RailVersionID: rail.VersionID, AssessmentID: assessment.ID, Status: "unavailable"}
	fact := resolvedFact{status: "unavailable"}
	input, err := observeInputBytes(request)
	if err != nil {
		return fact, summary
	}
	inputDigest := sha256.Sum256(input)
	attribution, err := json.Marshal(request.Attribution)
	if err != nil {
		return fact, summary
	}
	attributionDigest := sha256.Sum256(attribution)
	material := []string{}
	for _, target := range assessment.Fields {
		value, missing := resolve(target, args, result)
		text, ok := value.(string)
		if len(missing) != 0 || !ok {
			return fact, summary
		}
		material = append(material, text)
	}
	// Only a finding for this exact selected material and caller can supply a rule value.
	for _, signed := range request.ContextualFindings {
		value, err := s.decodeContextualFinding(signed, current)
		if err != nil || value.RailVersionID != rail.VersionID || value.AssessmentID != assessment.ID {
			continue
		}
		if value.OrganisationID != s.options.OrganisationID || value.DeploymentID != s.options.DeploymentID ||
			value.BundleID != manifest.BundleID || value.OperationVersionID != request.OperationVersionID ||
			value.RequestID != request.RequestID || value.Phase != request.Phase || value.InputSHA256 != hex.EncodeToString(inputDigest[:]) ||
			value.AttributionSHA256 != hex.EncodeToString(attributionDigest[:]) ||
			value.ExpiresAt.After(manifest.ExpiresAt) || !value.ExpiresAt.After(s.options.Now()) || value.IssuedAt.After(s.options.Now().Add(5*time.Second)) {
			fact.status, summary.Status = "untrusted", "untrusted"
			return fact, summary
		}
		// The material digest is generated with Go JSON by every maintained adapter.
		encoded, _ := json.Marshal(material)
		materialDigest := sha256.Sum256(encoded)
		if value.MaterialSHA256 != hex.EncodeToString(materialDigest[:]) {
			fact.status, summary.Status = "untrusted", "untrusted"
			return fact, summary
		}
		if summary.Finding != nil {
			fact.status, summary.Status, summary.Finding = "untrusted", "untrusted", nil
			return fact, summary
		}
		copy := signed
		summary.Finding = &copy
		switch value.Status {
		case "answered":
			if !validContextualValue(assessment.Answer, value.Value) {
				fact.status, summary.Status, summary.Finding = "untrusted", "untrusted", nil
				return fact, summary
			}
			fact.status, fact.value, summary.Status = "trusted", value.Value, "trusted"
		case "uncertain":
			fact.status, summary.Status = "untrusted", "uncertain"
		case "unavailable":
			fact.status, summary.Status = "unavailable", "unavailable"
		default:
			fact.status, summary.Status, summary.Finding = "untrusted", "untrusted", nil
		}
	}
	return fact, summary
}

func (s *Synchronizer) decodeContextualFinding(finding ContextualFinding, current *Configuration) (contextualValue, error) {
	var value contextualValue
	if current == nil || current.Bundle == nil || finding.Algorithm != "ECDSA_SHA_256" || finding.KeyID != current.Bundle.KeyID || len(finding.Payload) > 4096 {
		return value, errors.New("contextual finding is invalid")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(finding.Payload)
	if err != nil {
		return value, err
	}
	keyDER, err := base64.StdEncoding.Strict().DecodeString(current.Bundle.VerificationKey.Base64)
	if err != nil {
		return value, err
	}
	parsed, err := x509.ParsePKIXPublicKey(keyDER)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return value, errors.New("contextual key is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(finding.Signature)
	digest := sha256.Sum256(data)
	if err != nil || !ecdsa.VerifyASN1(key, digest[:], signature) {
		return value, errors.New("contextual signature is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Type != "authrail.contextual.finding.v1" {
		return value, errors.New("contextual finding is invalid")
	}
	return value, nil
}

func validContextualValue(answer contextualAnswer, value any) bool {
	switch answer.Type {
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "string":
		text, ok := value.(string)
		return ok && contains(answer.Choices, text)
	case "number":
		number, ok := value.(float64)
		return ok && number >= answer.Minimum && number <= answer.Maximum
	}
	return false
}
