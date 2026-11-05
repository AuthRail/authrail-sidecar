// Package setup connects a local application installation to its reviewed AuthRail deployment.
package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var identifier = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var fingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)
var secret = regexp.MustCompile(`^ars_[A-Za-z0-9_-]{43}$`)

type client struct {
	origin string
	http   *http.Client
	grant  grant
}

type grant struct {
	AccessToken    string    `json:"accessToken"`
	OrganisationID string    `json:"organisationId"`
	DeploymentID   string    `json:"deploymentId"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type connection struct {
	OrganisationID string       `json:"organisationId"`
	DeploymentID   string       `json:"deploymentId"`
	TrustedPins    []string     `json:"trustedKeyFingerprints"`
	Integration    *integration `json:"integration"`
	ExecutorKeys   []struct {
		SHA256 string `json:"keySha256"`
		Status string `json:"status"`
	} `json:"executorKeys"`
}

type integration struct {
	Mode       string           `json:"mode"`
	Sequence   int64            `json:"sequence"`
	ExpiresAt  time.Time        `json:"expiresAt"`
	Operations []setupOperation `json:"operations"`
}

type setupOperation struct {
	VersionID         string   `json:"operationVersionId"`
	Summary           string   `json:"summary"`
	RequiredCoverage  []string `json:"requiredCoverage"`
	ApprovalSupported bool     `json:"approvalSupported"`
	RequiresResource  bool     `json:"requiresResource"`
	RequiresFacts     bool     `json:"requiresFacts"`
}

func newClient(origin string) (*client, error) {
	uri, err := url.Parse(origin)
	if err != nil || !safeURL(uri) || uri.Path != "" && uri.Path != "/" {
		return nil, errors.New("set --api-url to your AuthRail HTTPS API origin; HTTP is allowed only on explicit loopback")
	}
	uri.Path = ""
	return &client{origin: uri.String(), http: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func safeURL(uri *url.URL) bool {
	return uri != nil && uri.Host != "" && uri.User == nil && uri.RawQuery == "" && uri.Fragment == "" &&
		(uri.Scheme == "https" || uri.Scheme == "http" &&
			(uri.Hostname() == "127.0.0.1" || uri.Hostname() == "::1" || uri.Hostname() == "localhost"))
}

func (c *client) request(ctx context.Context, method, path string, body, output any) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("cannot prepare setup request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("cannot prepare setup request")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.grant.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.grant.AccessToken)
		req.Header.Set("X-Organisation-Id", c.grant.OrganisationID)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("AuthRail could not be reached; check the API address and connection")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Provider and proxy bodies may contain credentials or internal diagnostics.
		return fmt.Errorf("AuthRail rejected setup (HTTP %d); check your access and deployment, then start setup again", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || json.Unmarshal(data, output) != nil {
		return errors.New("AuthRail returned an invalid setup response")
	}
	return nil
}

func (c *client) browserURL(ctx context.Context) (*url.URL, error) {
	var config struct {
		WorkspaceURL string `json:"workspaceUrl"`
	}
	if err := c.request(ctx, http.MethodGet, "/auth/runtime-setup/configuration", nil, &config); err != nil {
		return nil, err
	}
	uri, err := url.Parse(config.WorkspaceURL)
	if err != nil || !safeURL(uri) || uri.Path != "/runtime/setup" {
		return nil, errors.New("AuthRail returned an invalid browser setup address")
	}
	api, _ := url.Parse(c.origin)
	if api.Scheme == "https" && uri.Scheme != "https" {
		return nil, errors.New("the AuthRail sign-in page must use HTTPS")
	}
	return uri, nil
}

func (c *client) exchange(ctx context.Context, code, verifier, callback string) error {
	var result grant
	if err := c.request(ctx, http.MethodPost, "/auth/runtime-setup/exchange", map[string]string{
		"code": code, "codeVerifier": verifier, "redirectUri": callback,
	}, &result); err != nil {
		return err
	}
	if !secret.MatchString(result.AccessToken) || !identifier.MatchString(result.OrganisationID) ||
		!identifier.MatchString(result.DeploymentID) || !result.ExpiresAt.After(time.Now()) ||
		result.ExpiresAt.After(time.Now().Add(11*time.Minute)) {
		return errors.New("AuthRail returned an invalid setup grant")
	}
	c.grant = result
	return nil
}

func (c *client) connection(ctx context.Context) (connection, error) {
	var result struct {
		Setup connection `json:"setup"`
	}
	if err := c.request(ctx, http.MethodGet, "/runtime/setup/connection", nil, &result); err != nil {
		return connection{}, err
	}
	value := result.Setup
	if value.OrganisationID != c.grant.OrganisationID || value.DeploymentID != c.grant.DeploymentID ||
		len(value.TrustedPins) < 1 || len(value.TrustedPins) > 2 {
		return connection{}, errors.New("setup values do not match the confirmed deployment")
	}
	for _, pin := range value.TrustedPins {
		if !fingerprint.MatchString(pin) {
			return connection{}, errors.New("invalid AuthRail signing key fingerprint")
		}
	}
	if value.Integration != nil {
		selected := value.Integration
		if (selected.Mode != "observe" && selected.Mode != "enforce") || selected.Sequence < 1 ||
			selected.ExpiresAt.IsZero() || len(selected.Operations) > 100 {
			return connection{}, errors.New("AuthRail returned invalid selected action details")
		}
		seen := map[string]bool{}
		for _, operation := range selected.Operations {
			if !identifier.MatchString(operation.VersionID) || seen[operation.VersionID] || len(operation.Summary) > 960 {
				return connection{}, errors.New("AuthRail returned invalid selected action details")
			}
			seen[operation.VersionID] = true
		}
	}
	return value, nil
}
