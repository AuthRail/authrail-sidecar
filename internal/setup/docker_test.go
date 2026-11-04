package setup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Risks: published-image installation must not expose credentials/ports or lose
// private state when stopped, removed and recreated. This uses real Docker;
// an intentionally unreachable .invalid API cannot establish connected readiness.
func TestPublishedDockerInstallationRetainsPrivateState(t *testing.T) {
	if os.Getenv("AUTHRAIL_SETUP_DOCKER_TEST") != "1" {
		t.Skip("opt in to disposable Docker verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	directory := privateTestDirectory(t)
	key, err := prepareKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	token, err := prepareCredentials(directory)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(token, ".")[1]
	value := connection{OrganisationID: "11111111-1111-4111-8111-111111111111", DeploymentID: id, TrustedPins: []string{strings.Repeat("a", 64)}}
	if err := saveConnection(directory, "https://setup-verification.invalid", value, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	installation, err := dockerFor(directory, "https://setup-verification.invalid", value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		container, err := installation.inspect(cleanup)
		if err == nil && container != nil {
			_, _ = dockerCommand(cleanup, nil, "rm", "-f", container.ID)
		}
		for _, volume := range []string{installation.credentialsVolume, installation.stateVolume} {
			if err := installation.ownedVolume(cleanup, volume, false); err == nil {
				_, _ = dockerCommand(cleanup, nil, "volume", "rm", volume)
			}
		}
	})
	// A cached immutable digest is sufficient; a registry outage must not force a tag fallback.
	if _, err := dockerCommand(ctx, nil, "image", "inspect", publishedImage); err != nil {
		if _, err := dockerCommand(ctx, nil, "pull", publishedImage); err != nil {
			t.Fatal(err)
		}
	}
	start := func() {
		deadline, stop := context.WithTimeout(ctx, 12*time.Second)
		defer stop()
		if err := installation.start(deadline, io.Discard); err == nil {
			t.Fatal("unreachable API incorrectly established readiness")
		}
	}
	start()
	container, err := installation.inspect(ctx)
	if err != nil || container == nil || !container.State.Running {
		t.Fatalf("sidecar did not start: %v", err)
	}
	firstID := container.ID
	if err := runNative(ctx, directory, "https://setup-verification.invalid", "127.0.0.1:7078", value, io.Discard); err == nil {
		t.Fatal("a Docker installation was silently switched to native state")
	}
	data, err := dockerCommand(ctx, nil, "cp", container.ID+":/run/secrets/.", "-")
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(data))
	files := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name != "deployment-token" && name != "adapter-token" && name != "executor-public.pem" {
			t.Fatalf("unexpected secret volume file: %s", name)
		}
		if header.Mode != 0400 || header.Uid != 10001 || header.Gid != 10001 {
			t.Fatal("private volume file ownership or permissions are unsafe")
		}
		files[name] = true
	}
	if len(files) != 3 {
		t.Fatal("sidecar did not receive its exact three private files")
	}
	var marker bytes.Buffer
	archive := tar.NewWriter(&marker)
	if err := archive.WriteHeader(&tar.Header{Name: "setup-retention-marker", Mode: 0600, Uid: 10001, Gid: 10001, Size: 8}); err != nil {
		t.Fatal(err)
	}
	_, _ = archive.Write([]byte("retained"))
	_ = archive.Close()
	if _, err := dockerCommand(ctx, &marker, "cp", "-a", "-", container.ID+":/var/lib/authrail"); err != nil {
		t.Fatal(err)
	}
	if err := Installation(ctx, []string{"stop", "--directory", directory}, io.Discard); err != nil {
		t.Fatal(err)
	}
	container, err = installation.inspect(ctx)
	if err != nil || container == nil || container.State.Running {
		t.Fatal("stop failed")
	}
	start()
	container, err = installation.inspect(ctx)
	if err != nil || container == nil || container.ID != firstID {
		t.Fatal("restart replaced the container")
	}
	if err := Installation(ctx, []string{"remove", "--directory", directory}, io.Discard); err != nil {
		t.Fatal(err)
	}
	start()
	container, err = installation.inspect(ctx)
	if err != nil || container == nil || container.ID == firstID {
		t.Fatal("container recreation failed")
	}
	retained, err := dockerCommand(ctx, nil, "cp", container.ID+":/var/lib/authrail/setup-retention-marker", "-")
	if err != nil || !bytes.Contains(retained, []byte("retained")) {
		t.Fatal("container removal lost private state")
	}
	// A different directory must never stop or adopt this deployment's container.
	otherDirectory := privateTestDirectory(t)
	other, err := dockerFor(otherDirectory, "https://setup-verification.invalid", value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.inspect(ctx); err == nil {
		t.Fatal("a different installation adopted the container")
	}
	if err := Installation(ctx, []string{"remove", "--directory", directory}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerCommand(ctx, nil, "volume", "rm", installation.stateVolume); err != nil {
		t.Fatal(err)
	}
	if err := installation.start(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal("a lost state volume was silently recreated")
	}
}
