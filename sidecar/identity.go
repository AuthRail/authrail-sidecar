package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

// IdentityProof is an assertion made by the protected executor, not by the agent.
type IdentityProof struct {
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Signature string `json:"signature"`
}

type IdentityVerification struct {
	KeySHA256       string `json:"keySha256"`
	SignatureSHA256 string `json:"signatureSha256"`
}

func (s *Synchronizer) identityVerification(request EvaluationRequest, actionKey string) IdentityVerification {
	key, _ := s.matchExecutorKey(request, actionKey)
	keyDigest := sha256.Sum256(key)
	signature, _ := base64.RawURLEncoding.DecodeString(request.IdentityProof.Signature)
	signatureDigest := sha256.Sum256(signature)
	return IdentityVerification{KeySHA256: hex.EncodeToString(keyDigest[:]),
		SignatureSHA256: hex.EncodeToString(signatureDigest[:])}
}

type identityStatement struct {
	Type               string      `json:"type"`
	OrganisationID     string      `json:"organisationId"`
	DeploymentID       string      `json:"deploymentId"`
	RequestID          string      `json:"requestId"`
	ActionKey          string      `json:"actionKey"`
	OperationVersionID string      `json:"operationVersionId"`
	Phase              string      `json:"phase"`
	InputSHA256        string      `json:"inputSha256"`
	Attribution        Attribution `json:"attribution"`
	IssuedAt           int64       `json:"issuedAt"`
	ExpiresAt          int64       `json:"expiresAt"`
}

func LoadExecutorPublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("executor public key path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("executor public key cannot be read")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, errors.New("executor public key must be a single PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("executor public key must be Ed25519")
	}
	return key, nil
}

func (s *Synchronizer) verifyIdentityProof(request EvaluationRequest, actionKey string) error {
	_, err := s.matchExecutorKey(request, actionKey)
	return err
}

func (s *Synchronizer) matchExecutorKey(request EvaluationRequest, actionKey string) (ed25519.PublicKey, error) {
	proof := request.IdentityProof
	now := s.options.Now
	if now == nil {
		now = time.Now
	}
	issued, expires, current := time.Unix(proof.IssuedAt, 0), time.Unix(proof.ExpiresAt, 0), now()
	if len(s.options.ExecutorPublicKeys) == 0 ||
		proof.IssuedAt <= 0 || proof.ExpiresAt <= proof.IssuedAt ||
		expires.Sub(issued) > 60*time.Second ||
		issued.After(current.Add(5*time.Second)) || !expires.After(current) ||
		!uuidPattern.MatchString(request.RequestID) ||
		!uuidPattern.MatchString(request.OperationVersionID) ||
		(request.Phase != "tool_call" && request.Phase != "tool_result") {
		return nil, errors.New("executor identity proof is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("executor identity proof is invalid")
	}
	input, err := observeInputBytes(request)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(input)
	statement := identityStatement{Type: "authrail.observe.executor.v1",
		OrganisationID: s.options.OrganisationID, DeploymentID: s.options.DeploymentID,
		RequestID: request.RequestID, ActionKey: actionKey,
		OperationVersionID: request.OperationVersionID, Phase: request.Phase,
		InputSHA256: hex.EncodeToString(digest[:]), Attribution: request.Attribution,
		IssuedAt: proof.IssuedAt, ExpiresAt: proof.ExpiresAt}
	message, err := json.Marshal(statement)
	if err != nil {
		return nil, errors.New("executor identity proof is invalid")
	}
	for _, key := range s.options.ExecutorPublicKeys {
		if ed25519.Verify(key, message, signature) {
			return key, nil
		}
	}
	return nil, errors.New("executor identity proof is invalid")
}
