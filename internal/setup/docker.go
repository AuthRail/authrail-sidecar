package setup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Pin the published multi-platform artifact; setup never substitutes a mutable tag.
const publishedImage = "ghcr.io/authrail/authrail-sidecar@sha256:cb6e60475146ead55bcec56d5da14fcc75e2bf7e776b584b01ace5426a5356f4"
const installationLabel = "io.authrail.setup.installation"

type dockerInstallation struct {
	owner, container, stateVolume, credentialsVolume string
	directory, origin                                string
	connection                                       connection
}

type dockerContainer struct {
	ID     string `json:"Id"`
	Config struct {
		Image  string
		User   string
		Env    []string
		Labels map[string]string
	}
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		NetworkMode    string
		PortBindings   map[string]json.RawMessage
		CapDrop        []string
		CapAdd         []string
		SecurityOpt    []string
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	State struct {
		Running bool
		Status  string
	}
}

func dockerFor(directory, origin string, value connection) (*dockerInstallation, error) {
	api, err := url.Parse(origin)
	if err != nil || !safeURL(api) || api.Path != "" || api.Scheme != "https" || api.Hostname() == "localhost" || api.Hostname() == "127.0.0.1" || api.Hostname() == "::1" {
		return nil, errors.New("Docker setup needs an HTTPS API reachable from containers; a host-loopback API requires a reviewed container network arrangement")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("cannot identify the application configuration directory")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, errors.New("cannot identify the private installation directory")
	}
	digest := sha256.Sum256([]byte(origin + "\n" + value.OrganisationID + "\n" + value.DeploymentID + "\n" + canonical))
	name := "authrail-" + value.DeploymentID
	return &dockerInstallation{owner: hex.EncodeToString(digest[:]), container: name,
		stateVolume: name + "-state", credentialsVolume: name + "-credentials", directory: canonical, origin: origin, connection: value}, nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1024*1024 {
		return 0, errors.New("Docker response exceeds the setup limit")
	}
	return b.Buffer.Write(data)
}

func dockerCommand(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	var output boundedOutput
	command.Stdout = &output
	command.Stdin = input
	// Docker diagnostics can contain operator configuration. Keep them out of transcripts.
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("Docker operation failed; check Docker and this installation before retrying")
	}
	return output.Bytes(), nil
}

func (d *dockerInstallation) ownedVolume(ctx context.Context, name string, allowCreate bool) error {
	list, err := dockerCommand(ctx, nil, "volume", "ls", "--format", "{{.Name}}", "--filter", "name=^"+name+"$")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(list)) == "" {
		if !allowCreate {
			return errors.New("a retained installation volume is missing; restore its state before restarting, rather than creating empty state")
		}
		if _, err := dockerCommand(ctx, nil, "volume", "create", "--label", installationLabel+"="+d.owner, name); err != nil {
			return err
		}
	}
	data, err := dockerCommand(ctx, nil, "volume", "inspect", name)
	var values []struct {
		Name   string
		Labels map[string]string
	}
	if err != nil || json.Unmarshal(data, &values) != nil || len(values) != 1 || values[0].Name != name || values[0].Labels[installationLabel] != d.owner {
		return errors.New("an existing Docker volume belongs to a different installation; it was left unchanged")
	}
	return nil
}

func (d *dockerInstallation) receipt() (bool, error) {
	root, err := privateRoot(d.directory)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if _, err := root.Lstat("native-installation"); !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("this directory has a native installation; review its state and pause it before arranging a Docker migration")
	}
	data, err := readPrivate(root, "docker-installation")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || string(data) != d.owner+"\n"+publishedImage+"\n" {
		return false, errors.New("the saved Docker installation does not match this configuration; existing state was left unchanged")
	}
	return true, nil
}

func (d *dockerInstallation) retainReceipt() error {
	exists, err := d.receipt()
	if err != nil || exists {
		return err
	}
	root, err := privateRoot(d.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	return createPrivate(root, "docker-installation", []byte(d.owner+"\n"+publishedImage+"\n"))
}

func (d *dockerInstallation) inspect(ctx context.Context) (*dockerContainer, error) {
	list, err := dockerCommand(ctx, nil, "ps", "-a", "--format", "{{.ID}}", "--filter", "name=^/"+d.container+"$")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(list)) == "" {
		return nil, nil
	}
	data, err := dockerCommand(ctx, nil, "inspect", "--type", "container", d.container)
	var values []dockerContainer
	if err != nil || json.Unmarshal(data, &values) != nil || len(values) != 1 {
		return nil, errors.New("cannot inspect this Docker installation")
	}
	value := &values[0]
	if value.Config.Labels[installationLabel] != d.owner || value.Config.Image != publishedImage ||
		value.Config.User != "10001:10001" || !value.HostConfig.ReadonlyRootfs || value.HostConfig.Privileged ||
		len(value.HostConfig.PortBindings) != 0 || len(value.HostConfig.CapAdd) != 0 ||
		value.HostConfig.NetworkMode != "bridge" || !has(value.HostConfig.CapDrop, "ALL") ||
		!has(value.HostConfig.SecurityOpt, "no-new-privileges:true") || len(value.Mounts) != 2 {
		return nil, errors.New("the existing container does not match this private installation; it was left unchanged")
	}
	for _, mount := range value.Mounts {
		if mount.Type != "volume" || !(mount.Name == d.stateVolume && mount.Destination == "/var/lib/authrail" && mount.RW ||
			mount.Name == d.credentialsVolume && mount.Destination == "/run/secrets" && !mount.RW) {
			return nil, errors.New("the existing container has unexpected storage; it was left unchanged")
		}
	}
	for _, expected := range d.environment() {
		if !has(value.Config.Env, expected) {
			return nil, errors.New("the existing container has different connection settings; review it before changing this installation")
		}
	}
	return value, nil
}

func has(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (d *dockerInstallation) environment() []string {
	return []string{"AUTHRAIL_CONTROL_PLANE_URL=" + d.origin, "AUTHRAIL_ORGANISATION_ID=" + d.connection.OrganisationID,
		"AUTHRAIL_DEPLOYMENT_ID=" + d.connection.DeploymentID, "AUTHRAIL_TRUSTED_KEY_SHA256=" + strings.Join(d.connection.TrustedPins, ","),
		"AUTHRAIL_DEPLOYMENT_TOKEN_FILE=/run/secrets/deployment-token", "AUTHRAIL_ADAPTER_TOKEN_FILE=/run/secrets/adapter-token",
		"AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE=/run/secrets/executor-public.pem"}
}

func (d *dockerInstallation) populateCredentials(ctx context.Context) error {
	root, err := privateRoot(d.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range []string{"deployment-token", "adapter-token", "executor-public.pem"} {
		data, err := readPrivate(root, name)
		if err != nil {
			return errors.New("cannot read the private sidecar credential files")
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0400, Uid: 10001, Gid: 10001, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	// Copy through stdin into a stopped disposable container: no secrets in argv,
	// environment, image layers or host files with loosened permissions.
	helper, err := dockerCommand(ctx, nil, "create", "--network", "none", "--label", installationLabel+"="+d.owner,
		"--mount", "type=volume,src="+d.credentialsVolume+",dst=/run/secrets", publishedImage)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(helper))
	if len(id) != 64 {
		return errors.New("Docker returned an invalid temporary container identity")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = dockerCommand(cleanup, nil, "rm", id)
	}()
	_, err = dockerCommand(ctx, bytes.NewReader(archive.Bytes()), "cp", "-a", "-", id+":/run/secrets")
	return err
}

func (d *dockerInstallation) start(ctx context.Context, output io.Writer) error {
	if _, err := dockerCommand(ctx, nil, "info", "--format", "{{.ServerVersion}}"); err != nil {
		return err
	}
	container, err := d.inspect(ctx)
	if err != nil {
		return err
	}
	retained, err := d.receipt()
	if err != nil {
		return err
	}
	if err := bindRuntime(d.directory, "docker"); err != nil {
		return err
	}
	if container != nil && !retained {
		return errors.New("the installation record is missing; restore it before operating the existing container")
	}
	for _, volume := range []string{d.stateVolume, d.credentialsVolume} {
		if err := d.ownedVolume(ctx, volume, !retained); err != nil {
			return err
		}
	}
	if err := d.retainReceipt(); err != nil {
		return err
	}
	if container == nil {
		if _, err := dockerCommand(ctx, nil, "image", "inspect", publishedImage); err != nil {
			fmt.Fprintln(output, "Downloading the published AuthRail sidecar image…")
			if _, err := dockerCommand(ctx, nil, "pull", publishedImage); err != nil {
				return err
			}
		}
		version, err := dockerCommand(ctx, nil, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges:true", "--entrypoint", "/usr/local/bin/authrail-sidecar", publishedImage, "--version")
		var build struct {
			Version, Revision                              string
			BundleFormat, LocalProtocolFormat, StateFormat int
		}
		if err != nil || json.Unmarshal(version, &build) != nil || build.Version != "0.1.0" ||
			build.Revision != "5547cc5041558aaa23437b484e7a789600de6c5e" || build.BundleFormat != 1 || build.LocalProtocolFormat != 1 || build.StateFormat != 1 {
			return errors.New("the published image does not match the supported sidecar contract")
		}
		if err := d.populateCredentials(ctx); err != nil {
			return err
		}
		args := []string{"create", "--name", d.container, "--label", installationLabel + "=" + d.owner, "--network", "bridge",
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--restart", "unless-stopped",
			"--stop-timeout", "15", "--mount", "type=volume,src=" + d.stateVolume + ",dst=/var/lib/authrail",
			"--mount", "type=volume,src=" + d.credentialsVolume + ",dst=/run/secrets,readonly"}
		for _, value := range d.environment() {
			args = append(args, "--env", value)
		}
		args = append(args, publishedImage)
		if _, err := dockerCommand(ctx, nil, args...); err != nil {
			return err
		}
		container, err = d.inspect(ctx)
		if err != nil || container == nil {
			return errors.New("the new sidecar container could not be verified")
		}
	}
	if !container.State.Running {
		if _, err := dockerCommand(ctx, nil, "start", container.ID); err != nil {
			return err
		}
	}
	fmt.Fprintln(output, "Sidecar started. Waiting for its signed rules…")
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		if _, err := dockerCommand(deadline, nil, "exec", container.ID, "/usr/local/bin/authrail-container", "health"); err == nil {
			fmt.Fprintln(output, "Sidecar has a valid signed rule bundle. No protected application request has been verified yet.")
			fmt.Fprintln(output, "The application must run in a container with --network container:"+d.container+" and use http://127.0.0.1:7078.")
			fmt.Fprintln(output, "Its adapter token and private application key stay in the protected application. The agent must not join this network namespace.")
			return nil
		}
		select {
		case <-deadline.Done():
			return errors.New("sidecar is installed but has no usable signed rules; check the deployment's selected Rails and connection, then rerun setup; state and credentials were retained")
		case <-time.After(time.Second):
		}
	}
}
