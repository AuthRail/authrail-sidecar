package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// A retained receipt must be one complete bounded object, not a valid prefix
// followed by unchecked bytes. Unknown fields remain forward compatible.
func decodeControlPlaneResponse(body io.Reader, maximum int64, target any) error {
	encoded, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || int64(len(encoded)) > maximum {
		return errors.New("control plane response exceeds its size limit")
	}
	encoded = bytes.TrimSpace(encoded)
	if len(encoded) == 0 || encoded[0] != '{' || json.Unmarshal(encoded, target) != nil {
		return errors.New("control plane response is not a complete JSON object")
	}
	return nil
}
