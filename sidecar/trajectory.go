package sidecar

import (
	"encoding/json"
	"regexp"
	"strings"
)

var trajectoryFieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)

type TrajectorySnapshot struct {
	SessionID                    string         `json:"sessionId"`
	Start                        bool           `json:"start,omitempty"`
	Complete                     bool           `json:"complete"`
	PriorReadOperationVersionIDs []string       `json:"priorReadOperationVersionIds"`
	Values                       map[string]any `json:"values,omitempty"`
	verified                     bool           `json:"-"`
}

func validTrajectory(snapshot *TrajectorySnapshot, sessionID string) bool {
	if snapshot == nil {
		return true
	}
	if snapshot.SessionID != sessionID || !identityRefPattern.MatchString(snapshot.SessionID) ||
		len(snapshot.PriorReadOperationVersionIDs) > 256 ||
		(!snapshot.Complete && (len(snapshot.PriorReadOperationVersionIDs) != 0 || len(snapshot.Values) != 0)) {
		return false
	}
	if snapshot.Values != nil {
		encoded, err := json.Marshal(snapshot.Values)
		if err != nil || len(encoded) > 8*1024 || !validTrajectoryValues(snapshot.Values, 0) {
			return false
		}
	}
	seen := make(map[string]struct{}, len(snapshot.PriorReadOperationVersionIDs))
	for _, versionID := range snapshot.PriorReadOperationVersionIDs {
		if !uuidPattern.MatchString(versionID) || strings.ToLower(versionID) != versionID {
			return false
		}
		if _, duplicate := seen[versionID]; duplicate {
			return false
		}
		seen[versionID] = struct{}{}
	}
	return true
}

func validTrajectoryValues(values map[string]any, depth int) bool {
	if depth > 8 || len(values) > 80 {
		return false
	}
	for key, value := range values {
		if !trajectoryFieldPattern.MatchString(key) || key == "priorReadOperationVersionIds" {
			return false
		}
		switch typed := value.(type) {
		case string:
			if len(typed) > 1024 {
				return false
			}
		case bool:
		case float64:
		case json.Number:
			if !validFactValue(typed, "number") {
				return false
			}
		case map[string]any:
			if !validTrajectoryValues(typed, depth+1) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func reviewedTrajectoryValues(values map[string]any, fields []availableField) bool {
	if len(values) == 0 {
		return true
	}
	allowed := make(map[string]string)
	for _, field := range fields {
		if field.Root == "trajectory" && len(field.Path) > 0 {
			allowed[strings.Join(field.Path, ".")] = field.Type
		}
	}
	var check func(map[string]any, []string) bool
	check = func(current map[string]any, path []string) bool {
		for key, value := range current {
			fieldPath := append(append([]string(nil), path...), key)
			if nested, ok := value.(map[string]any); ok {
				if len(nested) == 0 || !check(nested, fieldPath) {
					return false
				}
				continue
			}
			switch allowed[strings.Join(fieldPath, ".")] {
			case "string":
				if _, ok := value.(string); !ok {
					return false
				}
			case "boolean":
				if _, ok := value.(bool); !ok {
					return false
				}
			case "number":
				if !validFactValue(value, "number") {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return check(values, nil)
}
