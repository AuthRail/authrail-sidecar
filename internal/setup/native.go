package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A native installation runs in the foreground. Closing it gracefully stops only
// this child; the caller's state, signing key and credentials remain on disk.
func runNative(ctx context.Context, directory, origin, address string, value connection, output io.Writer) error {
	if _, err := newClient(origin); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || (host != "127.0.0.1" && host != "::1") || port == "0" {
		return errors.New("native --listen must name an explicit loopback address and nonzero port")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return errors.New("cannot identify the native installation directory")
	}
	root, err := privateRoot(absolute)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat("docker-installation"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("this directory has a Docker installation; review its state before arranging a native migration")
	}
	if err := bindRuntime(directory, "native"); err != nil {
		return err
	}
	token, err := readPrivate(root, "deployment-token")
	if err != nil {
		return errors.New("native setup needs its saved deployment credential")
	}
	adapter, err := readPrivate(root, "adapter-token")
	if err != nil {
		return errors.New("native setup needs its saved adapter token")
	}
	if !deploymentTokenPattern.MatchString(strings.TrimSpace(string(token))) || !adapterTokenPattern.MatchString(strings.TrimSpace(string(adapter))) {
		return errors.New("saved native credentials are invalid")
	}
	if _, err := readPrivate(root, "executor-private.pem"); err != nil {
		return errors.New("the application's original private key must be present")
	}
	key, err := prepareKey(absolute)
	if err != nil {
		return err
	}
	state := filepath.Join(absolute, "native-state")
	receipt, receiptErr := readPrivate(root, "native-installation")
	if receiptErr == nil {
		if string(receipt) != "1\n" {
			return errors.New("the native installation version is unsupported")
		}
		if info, err := os.Lstat(state); err != nil || !info.IsDir() {
			return errors.New("native state is missing; restore it before restarting instead of creating empty state")
		}
	} else if !errors.Is(receiptErr, os.ErrNotExist) {
		return errors.New("cannot safely read the native installation record")
	}
	stateRoot, err := privateRoot(state)
	if err != nil {
		return err
	}
	stateRoot.Close()
	if errors.Is(receiptErr, os.ErrNotExist) {
		if err := createPrivate(root, "native-installation", []byte("1\n")); err != nil {
			return err
		}
	}
	logFile, err := root.OpenFile("sidecar.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := root.Lstat("sidecar.log")
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("the native log must be a private regular file")
		}
		logFile, err = root.OpenFile("sidecar.log", os.O_WRONLY|os.O_APPEND, 0600)
	}
	if err != nil {
		return errors.New("cannot open the private native process log")
	}
	defer logFile.Close()
	before, err := root.Lstat("sidecar.log")
	opened, statErr := logFile.Stat()
	if err != nil || statErr != nil || !before.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Mode().Perm()&0077 != 0 {
		return errors.New("the native log changed while it was opened; no data was written")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot locate the installed sidecar executable")
	}
	childCtx, stop := context.WithCancel(ctx)
	defer stop()
	command := exec.CommandContext(childCtx, executable)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 8 * time.Second
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "AUTHRAIL_") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Env = append(command.Env, "AUTHRAIL_CONTROL_PLANE_URL="+origin,
		"AUTHRAIL_ORGANISATION_ID="+value.OrganisationID, "AUTHRAIL_DEPLOYMENT_ID="+value.DeploymentID,
		"AUTHRAIL_TRUSTED_KEY_SHA256="+strings.Join(value.TrustedPins, ","),
		"AUTHRAIL_DEPLOYMENT_TOKEN="+strings.TrimSpace(string(token)), "AUTHRAIL_ADAPTER_TOKEN="+strings.TrimSpace(string(adapter)),
		"AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE="+filepath.Join(absolute, "executor-public.pem"),
		"AUTHRAIL_STATE_FILE="+filepath.Join(state, "state.json"), "AUTHRAIL_HEALTH_ADDR="+address)
	command.Stdout, command.Stderr = logFile, logFile
	// Do not borrow another installation's listener or terminate its process.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("the native listener is in use; the existing process was left unchanged")
	}
	listener.Close()
	if err := command.Start(); err != nil {
		return errors.New("cannot start the native sidecar")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() { stop(); <-done }()
	fmt.Fprintln(output, "Native sidecar started. Its private process log is:")
	fmt.Fprintln(output, filepath.Join(absolute, "sidecar.log"))
	fmt.Fprintln(output, "Waiting for signed rules. Press Ctrl+C to stop this process; saved state will be retained.")
	health := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for {
		select {
		case err := <-done:
			done <- err
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("native sidecar stopped; inspect its private log before restarting")
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
			if ready {
				continue
			}
			request, _ := http.NewRequestWithContext(childCtx, http.MethodGet, "http://"+address+"/health", nil)
			response, err := health.Do(request)
			if err != nil {
				continue
			}
			var snapshot struct {
				BundleValid bool   `json:"bundleValid"`
				Key         string `json:"executorKeySha256"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&snapshot)
			response.Body.Close()
			if err == nil && response.StatusCode == 200 && snapshot.BundleValid && snapshot.Key == key.Fingerprint {
				ready = true
				fmt.Fprintln(output, "Signed rules are ready. Connect your host application's SDK to http://"+address+".")
				fmt.Fprintln(output, "No protected application request has been verified yet.")
			}
		}
	}
}
