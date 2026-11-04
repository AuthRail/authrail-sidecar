package setup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var deploymentTokenPattern = regexp.MustCompile(`^arwd1\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.[A-Za-z0-9_-]{43}$`)
var adapterTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func prepareCredentials(directory string) (string, error) {
	root, err := privateRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	token, err := retainedSecret(root, "deployment-token", deploymentTokenPattern, func() (string, error) {
		id, secret := make([]byte, 16), make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			return "", err
		}
		if _, err := rand.Read(secret); err != nil {
			return "", err
		}
		id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
		return fmt.Sprintf("arwd1.%x-%x-%x-%x-%x.%s", id[:4], id[4:6], id[6:8], id[8:10], id[10:], base64.RawURLEncoding.EncodeToString(secret)), nil
	})
	if err != nil {
		return "", err
	}
	_, err = retainedSecret(root, "adapter-token", adapterTokenPattern, func() (string, error) {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return "", err
		}
		return hex.EncodeToString(secret), nil
	})
	return token, err
}

func retainedSecret(root *os.Root, name string, pattern *regexp.Regexp, generate func() (string, error)) (string, error) {
	data, err := readPrivate(root, name)
	if errors.Is(err, os.ErrNotExist) {
		value, err := generate()
		if err != nil {
			return "", errors.New("cannot generate a private application credential")
		}
		if err := createPrivate(root, name, []byte(value+"\n")); err != nil {
			return "", err
		}
		return value, nil
	}
	if err != nil {
		return "", errors.New("cannot safely read saved application credentials; existing files were preserved")
	}
	value := strings.TrimRight(string(data), "\r\n")
	if !pattern.MatchString(value) {
		return "", errors.New("a saved application credential is invalid; review it before restarting setup")
	}
	if name == "deployment-token" {
		parts := strings.Split(value, ".")
		decoded, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] {
			return "", errors.New("the saved deployment credential is invalid")
		}
	}
	return value, nil
}

func (c *client) registerCredential(ctx context.Context, token, keyFingerprint string) error {
	var result struct {
		Credential struct {
			ID         string    `json:"id"`
			Generation int       `json:"generation"`
			ExpiresAt  time.Time `json:"expiresAt"`
		} `json:"credential"`
	}
	if err := c.request(ctx, http.MethodPost, "/runtime/setup/credential", map[string]string{
		"token": token, "executorKeySha256": keyFingerprint,
	}, &result); err != nil {
		return err
	}
	match := deploymentTokenPattern.FindStringSubmatch(token)
	if len(match) != 2 || result.Credential.ID != match[1] || result.Credential.Generation < 1 ||
		!result.Credential.ExpiresAt.After(time.Now()) {
		return errors.New("AuthRail returned an unexpected deployment credential registration")
	}
	return nil
}
