package sidecar

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const credentialRedactionHandlerID = "authrail_redact_credentials_v1"
const credentialRedactionHandlerVersion = "cea4d8ac57cc39a33a9584742b56e412ff889026cb6b69b086bccbe4cc25d833"

var credentialTokenV1 = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|(?:AKIA|ASIA)[A-Z0-9]{16}`)

// credentialFormatV1 recognizes only the pinned credential formats. It does not
// classify arbitrary confidential text or establish whether a token is active.
func credentialFormatV1(input string) bool {
	for _, marker := range []string{
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if strings.Contains(input, marker) {
			return true
		}
	}
	for _, match := range credentialTokenV1.FindAllStringIndex(input, -1) {
		if (match[0] == 0 || !credentialTokenByte(input[match[0]-1])) &&
			(match[1] == len(input) || !credentialTokenByte(input[match[1]])) {
			return true
		}
	}
	return false
}

func credentialTokenByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' || value == '_'
}

func validCredentialComparison(node condition) bool {
	var profile string
	return node.Right.Kind == "literal" && json.Unmarshal(node.Right.Value, &profile) == nil && profile == "credential_formats_v1"
}

// Conservatively withhold a protected format before disclosure even when a
// surrounding business branch would not match. Final rule evaluation is unchanged.
func localDisclosureProtections(rail railBinding, phase string) ([]disclosureProtection, error) {
	fields := []disclosureProtection{}
	for _, raw := range rail.Content.Rules {
		var rule decisionRule
		if json.Unmarshal(raw, &rule) != nil {
			return nil, errors.New("invalid Guard rule")
		}
		if rule.Phase != phase || rule.Outcome != "deny" || rule.Kind != "" {
			continue
		}
		nodes := 0
		selected, err := collectDisclosureProtections(rule.When, 0, &nodes)
		if err != nil {
			return nil, err
		}
		fields = append(fields, selected...)
	}
	return fields, nil
}

func collectDisclosureProtections(raw json.RawMessage, depth int, nodes *int) ([]disclosureProtection, error) {
	*nodes = *nodes + 1
	if depth > 8 || *nodes > 64 {
		return nil, errors.New("Guard condition exceeds disclosure limits")
	}
	var node condition
	if json.Unmarshal(raw, &node) != nil {
		return nil, errors.New("invalid Guard condition")
	}
	fields := []disclosureProtection{}
	switch node.Kind {
	case "all", "any":
		if len(node.Conditions) < 1 || len(node.Conditions) > 16 {
			return nil, errors.New("invalid Guard condition")
		}
		for _, child := range node.Conditions {
			selected, err := collectDisclosureProtections(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			fields = append(fields, selected...)
		}
	case "not":
		return collectDisclosureProtections(node.Condition, depth+1, nodes)
	case "compare":
		if node.Comparison == "matches_credentials_v1" {
			if !validCredentialComparison(node) {
				return nil, errors.New("unsupported credential protection")
			}
			fields = append(fields, disclosureProtection{Field: node.Left, Profile: "credential_formats_v1"})
		}
		if node.Comparison == "matches_sensitive_v1" {
			profile, valid := validSensitiveComparison(node)
			if !valid {
				return nil, errors.New("unsupported sensitive-data protection")
			}
			fields = append(fields, disclosureProtection{Field: node.Left, Profile: profile})
		}
	default:
		return nil, errors.New("invalid Guard condition")
	}
	return fields, nil
}
