package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This isolated binary smoke test proves a clean private install and process
// restart without touching any existing sidecar or database.
func TestCleanBinaryRestartPreservesSequence(t *testing.T) {
	const organisationID = "11111111-1111-4111-8111-111111111111"
	const deploymentID = "22222222-2222-4222-8222-222222222222"
	var sequence atomic.Int64
	sequence.Store(1)
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/runtime/deployment/configuration" {
			if r.Header.Get("Authorization") != "Bearer isolated-deployment-token" {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"deployment": map[string]any{
				"organisationId": organisationID, "deploymentId": deploymentID,
				"inventoryItemId":     "33333333-3333-4333-8333-333333333333",
				"inventoryRevisionId": "44444444-4444-4444-8444-444444444444",
				"mode":                "observe", "sequence": sequence.Load(), "activeBundleId": nil}})
			return
		}
		w.WriteHeader(204)
	}))
	defer controlPlane.Close()
	root := t.TempDir()
	packageRoot := filepath.Join(root, "package")
	pack := exec.Command("sh", "../../scripts/package.sh", "test-v1", packageRoot)
	if output, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("clean package: %v %s", err, output)
	}
	name := "authrail-sidecar-test-v1-" + strings.TrimSpace(goEnv(t, "GOOS")) + "-" + strings.TrimSpace(goEnv(t, "GOARCH"))
	archive := filepath.Join(packageRoot, name+".tar.gz")
	verify := exec.Command("shasum", "-a", "256", "-c", name+".tar.gz.sha256")
	verify.Dir = packageRoot
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("package checksum: %v %s", err, output)
	}
	installRoot := filepath.Join(root, "installed")
	if err := os.Mkdir(installRoot, 0700); err != nil {
		t.Fatal(err)
	}
	unpack := exec.Command("tar", "-xzf", archive, "-C", installRoot)
	if output, err := unpack.CombinedOutput(); err != nil {
		t.Fatalf("package unpack: %v %s", err, output)
	}
	binary := filepath.Join(installRoot, name, "authrail-sidecar")
	// Verify the shipped executable agrees with its manifest without any credentials.
	versionOutput, err := exec.Command(binary, "--version").Output()
	if err != nil {
		t.Fatalf("package version: %v", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(installRoot, name, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var actual, manifest map[string]any
	if err := json.Unmarshal(versionOutput, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "revision", "bundleFormat", "localProtocolFormat", "stateFormat"} {
		if actual[key] != manifest[key] {
			t.Fatalf("binary/manifest mismatch for %s: %v != %v", key, actual[key], manifest[key])
		}
	}
	if actual["version"] != "test-v1" || actual["revision"] == "" {
		t.Fatalf("missing build identity: %v", actual)
	}
	stateFile := filepath.Join(root, "private", "state.json")
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	_ = port.Close()
	environment := append(os.Environ(),
		"AUTHRAIL_CONTROL_PLANE_URL="+controlPlane.URL,
		"AUTHRAIL_DEPLOYMENT_TOKEN=isolated-deployment-token",
		"AUTHRAIL_ORGANISATION_ID="+organisationID,
		"AUTHRAIL_DEPLOYMENT_ID="+deploymentID,
		"AUTHRAIL_TRUSTED_KEY_SHA256="+strings.Repeat("a", 64),
		"AUTHRAIL_STATE_FILE="+stateFile,
		"AUTHRAIL_HEALTH_ADDR="+address,
		"AUTHRAIL_SYNC_INTERVAL=1s")
	start := func() *exec.Cmd {
		cmd := exec.Command(binary)
		cmd.Env = environment
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	stop := func(cmd *exec.Cmd) {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Errorf("sidecar exit: %v", err)
		}
	}
	awaitSequence := func(expected int64) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			response, err := http.Get("http://" + address + "/health")
			if err == nil {
				var state struct {
					Sequence int64 `json:"sequence"`
				}
				_ = json.NewDecoder(response.Body).Decode(&state)
				response.Body.Close()
				if state.Sequence == expected {
					return
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("sidecar did not retain sequence %d", expected)
	}
	first := start()
	awaitSequence(1)
	stop(first)
	info, err := os.Stat(stateFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private state missing or unsafe: %v", err)
	}
	sequence.Store(0) // An old control-plane configuration cannot lower the retained floor.
	second := start()
	awaitSequence(1)
	stop(second)
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	output, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}
