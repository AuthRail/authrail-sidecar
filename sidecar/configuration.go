package sidecar

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const maxConfigurationBytes = 2 << 20

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Configuration struct {
	Deployment struct {
		OrganisationID    string  `json:"organisationId"`
		DeploymentID      string  `json:"deploymentId"`
		InventoryItemID   string  `json:"inventoryItemId"`
		InventoryRevision string  `json:"inventoryRevisionId"`
		Mode              string  `json:"mode"`
		Sequence          int64   `json:"sequence"`
		ActiveBundleID    *string `json:"activeBundleId"`
	} `json:"deployment"`
	Bundle *SignedBundle `json:"bundle"`
}

type SignedBundle struct {
	Payload         string `json:"payload"`
	KeyID           string `json:"keyId"`
	Algorithm       string `json:"algorithm"`
	Signature       string `json:"signature"`
	VerificationKey struct {
		Format string `json:"format"`
		Base64 string `json:"base64"`
		SHA256 string `json:"sha256"`
	} `json:"verificationKey"`
}

type Manifest struct {
	FormatVersion       int               `json:"formatVersion"`
	BundleID            string            `json:"bundleId"`
	OrganisationID      string            `json:"organisationId"`
	DeploymentID        string            `json:"deploymentId"`
	InventoryItemID     string            `json:"inventoryItemId"`
	InventoryRevisionID string            `json:"inventoryRevisionId"`
	Sequence            int64             `json:"sequence"`
	Mode                string            `json:"mode"`
	IssuedAt            time.Time         `json:"issuedAt"`
	ActiveFrom          time.Time         `json:"activeFrom"`
	ExpiresAt           time.Time         `json:"expiresAt"`
	Rails               []json.RawMessage `json:"rails"`
}

func decodeConfiguration(data []byte) (Configuration, error) {
	var value Configuration
	if len(data) == 0 || len(data) > maxConfigurationBytes {
		return value, errors.New("configuration size is invalid")
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("decode configuration: %w", err)
	}
	return value, nil
}

func verifyConfiguration(value Configuration, organisationID, deploymentID string,
	pins map[string]struct{}, now time.Time) (*Manifest, error) {
	d := value.Deployment
	if !uuidPattern.MatchString(d.OrganisationID) || !uuidPattern.MatchString(d.DeploymentID) ||
		!uuidPattern.MatchString(d.InventoryItemID) || !uuidPattern.MatchString(d.InventoryRevision) ||
		d.OrganisationID != organisationID || d.DeploymentID != deploymentID ||
		(d.Mode != "observe" && d.Mode != "enforce") || d.Sequence < 0 {
		return nil, errors.New("configuration audience or mode is invalid")
	}
	if d.ActiveBundleID == nil {
		if value.Bundle != nil {
			return nil, errors.New("inactive configuration includes a bundle")
		}
		return nil, nil
	}
	if value.Bundle == nil || !uuidPattern.MatchString(*d.ActiveBundleID) {
		return nil, errors.New("active configuration has no bundle")
	}
	b := value.Bundle
	if b.Algorithm != "ECDSA_SHA_256" || b.KeyID == "" ||
		b.VerificationKey.Format != "spki-der" {
		return nil, errors.New("bundle verification contract is invalid")
	}
	keyDER, err := base64.StdEncoding.Strict().DecodeString(b.VerificationKey.Base64)
	if err != nil || len(keyDER) == 0 || base64.StdEncoding.EncodeToString(keyDER) != b.VerificationKey.Base64 {
		return nil, errors.New("bundle verification key is invalid")
	}
	keyHash := sha256.Sum256(keyDER)
	fingerprint := hex.EncodeToString(keyHash[:])
	if fingerprint != b.VerificationKey.SHA256 {
		return nil, errors.New("bundle verification key fingerprint is inconsistent")
	}
	if _, trusted := pins[fingerprint]; !trusted {
		return nil, errors.New("bundle verification key is not pinned")
	}
	key, err := x509.ParsePKIXPublicKey(keyDER)
	if err != nil {
		return nil, errors.New("bundle verification key cannot be parsed")
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve.Params().Name != "P-256" {
		return nil, errors.New("bundle verification key has the wrong curve")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(b.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 1<<20 ||
		base64.RawURLEncoding.EncodeToString(payload) != b.Payload {
		return nil, errors.New("bundle payload is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(b.Signature)
	if err != nil || len(signature) == 0 || base64.StdEncoding.EncodeToString(signature) != b.Signature {
		return nil, errors.New("bundle signature is invalid")
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(ecKey, digest[:], signature) {
		return nil, errors.New("bundle signature does not verify")
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return nil, errors.New("bundle manifest cannot be parsed")
	}
	if manifest.FormatVersion != 1 || manifest.BundleID != *d.ActiveBundleID ||
		manifest.OrganisationID != organisationID || manifest.DeploymentID != deploymentID ||
		manifest.InventoryItemID != d.InventoryItemID ||
		manifest.InventoryRevisionID != d.InventoryRevision ||
		manifest.Sequence != d.Sequence || manifest.Sequence < 1 ||
		manifest.Mode != d.Mode || len(manifest.Rails) == 0 || len(manifest.Rails) > 100 ||
		manifest.IssuedAt.IsZero() || manifest.ActiveFrom.IsZero() || manifest.ExpiresAt.IsZero() ||
		manifest.IssuedAt.After(manifest.ActiveFrom) ||
		!manifest.ActiveFrom.Before(manifest.ExpiresAt) {
		return nil, errors.New("bundle manifest does not match deployment state")
	}
	if now.Before(manifest.ActiveFrom) || !now.Before(manifest.ExpiresAt) {
		return nil, errors.New("bundle is not within its validity window")
	}
	return &manifest, nil
}

func ParsePins(value string) (map[string]struct{}, error) {
	pins := make(map[string]struct{})
	for _, part := range strings.Split(value, ",") {
		pin := strings.TrimSpace(part)
		if pin == "" {
			continue
		}
		if len(pin) != 64 || strings.Trim(pin, "0123456789abcdef") != "" {
			return nil, errors.New("trusted key fingerprints must be lowercase SHA-256 hex")
		}
		pins[pin] = struct{}{}
	}
	if len(pins) == 0 {
		return nil, errors.New("at least one trusted signing key fingerprint is required")
	}
	return pins, nil
}
