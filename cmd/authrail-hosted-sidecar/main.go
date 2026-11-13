package main

import (
	"context"
	"errors"
	"github.com/AuthRail/authrail-sidecar/sidecar"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var version = "development"
var revision = "unknown"

func socketPath() string {
	if path := os.Getenv("AUTHRAIL_HOSTED_SOCKET"); path != "" {
		return path
	}
	return "/run/authrail/sidecar.sock"
}
func main() {
	path := socketPath()
	if len(os.Args) == 2 && os.Args[1] == "health" {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
		r, err := client.Get("http://unix/health/live")
		if err != nil {
			os.Exit(1)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		log.Fatal("hosted socket directory unavailable")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatal("hosted socket lock unavailable")
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		log.Fatal("hosted socket already owned")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if entry, err := os.Lstat(path); err == nil {
		if entry.Mode()&os.ModeSocket == 0 {
			log.Fatal("hosted socket path is occupied")
		}
		if os.Remove(path) != nil {
			log.Fatal("stale socket unavailable")
		}
	} else if !os.IsNotExist(err) {
		log.Fatal("hosted socket unavailable")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Fatal("hosted socket listen failed")
	}
	defer listener.Close()
	defer os.Remove(path)
	if os.Chmod(path, 0660) != nil {
		log.Fatal("hosted socket permissions failed")
	}
	telemetry, err := sidecar.NewTelemetry(ctx, os.Getenv("AUTHRAIL_OTLP_ENDPOINT"))
	if err != nil {
		log.Fatal("hosted telemetry configuration invalid")
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = telemetry.Shutdown(shutdown)
	}()
	evaluator := sidecar.NewHostedEvaluator(telemetry)
	server := &http.Server{Handler: telemetry.WrapHTTP("hosted", evaluator.Handler()), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(listener) }()
	log.Printf("AuthRail hosted evaluator ready version=%s revision=%s", version, revision)
	select {
	case <-ctx.Done():
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print("hosted evaluator stopped unexpectedly")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
}
