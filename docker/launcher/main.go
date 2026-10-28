//go:build linux

// The container launcher loads mounted credentials before replacing itself with
// the sidecar. Signals reach the decision process directly; no shell holds secrets.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "health" {
		if err := health(); err != nil {
			fmt.Fprintln(os.Stderr, "sidecar is not ready")
			os.Exit(1)
		}
		return
	}
	for _, name := range []string{"AUTHRAIL_DEPLOYMENT_TOKEN", "AUTHRAIL_ADAPTER_TOKEN", "AUTHRAIL_OPERATOR_TOKEN"} {
		path := os.Getenv(name + "_FILE")
		if path == "" {
			continue
		}
		if os.Getenv(name) != "" {
			fail(name + " and " + name + "_FILE cannot both be set")
		}
		file, err := os.Open(path)
		if err != nil {
			fail(name + "_FILE cannot be read")
		}
		value, err := io.ReadAll(io.LimitReader(file, 16385))
		file.Close()
		if err != nil || len(value) > 16384 || strings.TrimSpace(string(value)) == "" {
			fail(name + "_FILE must contain a bounded nonempty credential")
		}
		os.Setenv(name, strings.TrimRight(string(value), "\r\n"))
		os.Unsetenv(name + "_FILE")
	}
	if err := syscall.Exec("/usr/local/bin/authrail-sidecar", append([]string{"authrail-sidecar"}, os.Args[1:]...), os.Environ()); err != nil {
		fail("sidecar could not start")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func health() error {
	address := os.Getenv("AUTHRAIL_HEALTH_ADDR")
	if address == "" {
		address = "127.0.0.1:7078"
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://" + address + "/health")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var snapshot struct {
		BundleValid bool `json:"bundleValid"`
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health unavailable")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&snapshot); err != nil {
		return err
	}
	if !snapshot.BundleValid {
		return fmt.Errorf("no valid signed bundle")
	}
	return nil
}
