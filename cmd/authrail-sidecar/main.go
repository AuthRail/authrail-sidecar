package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AuthRail/authrail-sidecar/sidecar"
)

func main() {
	pins, err := sidecar.ParsePins(os.Getenv("AUTHRAIL_TRUSTED_KEY_SHA256"))
	if err != nil {
		log.Fatal(err)
	}
	adapterToken := os.Getenv("AUTHRAIL_ADAPTER_TOKEN")
	var executorPublicKey []byte
	var executorPublicKeys []ed25519.PublicKey
	if adapterToken != "" {
		if len(adapterToken) < 32 {
			log.Fatal("AUTHRAIL_ADAPTER_TOKEN must have at least 32 characters")
		}
		executorPublicKey, err = sidecar.LoadExecutorPublicKey(os.Getenv("AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE"))
		if err != nil {
			log.Fatal("AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE must contain an Ed25519 public key")
		}
		executorPublicKeys = append(executorPublicKeys, executorPublicKey)
		if previous := os.Getenv("AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE"); previous != "" {
			key, loadErr := sidecar.LoadExecutorPublicKey(previous)
			if loadErr != nil {
				log.Fatal("AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE must contain an Ed25519 public key")
			}
			executorPublicKeys = append(executorPublicKeys, key)
		}
	}
	interval := 5 * time.Second
	if value := os.Getenv("AUTHRAIL_SYNC_INTERVAL"); value != "" {
		interval, err = time.ParseDuration(value)
		if err != nil || interval < time.Second {
			log.Fatal("AUTHRAIL_SYNC_INTERVAL must be at least one second")
		}
	}
	synchronizer, err := sidecar.NewSynchronizer(sidecar.Options{
		ControlPlaneURL:    os.Getenv("AUTHRAIL_CONTROL_PLANE_URL"),
		Token:              os.Getenv("AUTHRAIL_DEPLOYMENT_TOKEN"),
		OrganisationID:     os.Getenv("AUTHRAIL_ORGANISATION_ID"),
		DeploymentID:       os.Getenv("AUTHRAIL_DEPLOYMENT_ID"),
		TrustedPins:        pins,
		ExecutorPublicKey:  executorPublicKey,
		ExecutorPublicKeys: executorPublicKeys,
		StateFile:          os.Getenv("AUTHRAIL_STATE_FILE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("AUTHRAIL_HEALTH_ADDR")
	if address == "" {
		address = "127.0.0.1:7078"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("sidecar health listener could not start")
	}
	if !listener.Addr().(*net.TCPAddr).IP.IsLoopback() {
		listener.Close()
		log.Fatal("sidecar health listener must bind to loopback")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(synchronizer.Snapshot())
	})
	if adapterToken != "" {
		mux.Handle("POST /evaluate", sidecar.EvaluationHandler(synchronizer, adapterToken))
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print("sidecar health listener stopped")
			stop()
		}
	}()
	log.Print("AuthRail sidecar configuration sync started")
	if err := synchronizer.Sync(ctx); err != nil && ctx.Err() == nil {
		log.Print("initial configuration sync: ", safeError(err))
	}
	go func() {
		retryTicker := time.NewTicker(15 * time.Second)
		defer retryTicker.Stop()
		for {
			if err := synchronizer.RetryObservations(ctx); err != nil && ctx.Err() == nil {
				log.Print("Observe reports remain queued")
			}
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
			}
		}
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = server.Shutdown(shutdown)
			cancel()
			return
		case <-ticker.C:
			if err := synchronizer.Sync(ctx); err != nil && ctx.Err() == nil {
				log.Print("configuration sync: ", safeError(err))
			}
		}
	}
}

func safeError(err error) string {
	// The synchronizer returns controlled errors; keep provider responses and
	// deployment credentials out of process logs.
	message := err.Error()
	if strings.Contains(message, "unauthorized") {
		return "deployment credential unauthorized"
	}
	return "configuration unavailable or invalid"
}
