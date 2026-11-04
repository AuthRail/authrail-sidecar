package setup

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Risks: setup must not rotate saved keys, follow substituted private files,
// reuse another deployment's directory, or accept a forged/replayed callback.
func TestApplicationKeysSurviveRerun(t *testing.T) {
	dir := privateTestDirectory(t)
	first, err := prepareKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(filepath.Join(dir, "executor-private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareKey(dir)
	if err != nil || first != second {
		t.Fatalf("saved key changed: %v", err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "executor-private.pem"))
	if string(private) != string(again) {
		t.Fatal("private key replaced")
	}
	if err := os.Chmod(filepath.Join(dir, "executor-private.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareKey(dir); err == nil {
		t.Fatal("accepted a publicly readable private key")
	}
}

func TestSetupRejectsSymlinkedKey(t *testing.T) {
	dir := privateTestDirectory(t)
	target := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(target, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "executor-private.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareKey(dir); err == nil {
		t.Fatal("accepted a symlinked private key")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "do not overwrite" {
		t.Fatal("changed the symlink target")
	}
}

func TestConnectionCannotReuseAnotherInstallation(t *testing.T) {
	dir := privateTestDirectory(t)
	first := connection{OrganisationID: "00000000-0000-4000-8000-000000000001", DeploymentID: "00000000-0000-4000-8000-000000000002", TrustedPins: []string{strings.Repeat("a", 64)}}
	if err := saveConnection(dir, "https://api.example.test", first, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := checkConnection(dir, "https://api.example.test", first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.DeploymentID = "00000000-0000-4000-8000-000000000003"
	if err := checkConnection(dir, "https://api.example.test", second); err == nil {
		t.Fatal("accepted another deployment")
	}
	if err := checkConnection(dir, "https://other.example.test", first); err == nil {
		t.Fatal("accepted another API")
	}
}

func TestCallbackRequiresTerminalStateAndExactHost(t *testing.T) {
	state := strings.Repeat("s", 43)
	value := strings.Repeat("c", 43)
	code := make(chan string, 1)
	handler := callbackHandler("http://127.0.0.1:43992/runtime/setup/callback", state, code)
	send := func(host, nonce string) int {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/runtime/setup/callback?code="+value+"&state="+nonce, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	if send("127.0.0.1:43992", "wrong") != 400 || send("attacker.example", state) != 400 {
		t.Fatal("accepted a forged callback")
	}
	if send("127.0.0.1:43992", state) != 200 {
		t.Fatal("rejected terminal callback")
	}
	if <-code != value {
		t.Fatal("wrong code delivered")
	}
	if send("127.0.0.1:43992", state) != 409 {
		t.Fatal("accepted a repeated callback after the first code was consumed")
	}
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
