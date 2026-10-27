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
	operatorToken := os.Getenv("AUTHRAIL_OPERATOR_TOKEN")
	if operatorToken != "" && (len(operatorToken) < 32 ||
		operatorToken == adapterToken || operatorToken == os.Getenv("AUTHRAIL_DEPLOYMENT_TOKEN")) {
		log.Fatal("AUTHRAIL_OPERATOR_TOKEN must be a separate secret of at least 32 characters")
	}
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
	telemetry, err := sidecar.NewTelemetry(context.Background(), os.Getenv("AUTHRAIL_OTLP_ENDPOINT"))
	if err != nil {
		log.Print("sidecar telemetry export unavailable; continuing without export")
		telemetry, _ = sidecar.NewTelemetry(context.Background(), "")
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
		// The adapter and operator tokens are only safe on a local listener.
		listener.Close()
		log.Fatal("sidecar health listener must bind to loopback")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(struct {
			sidecar.Snapshot
			TelemetryFailures uint64 `json:"telemetryFailures"`
		}{synchronizer.Snapshot(), telemetry.Failures()})
	})
	if adapterToken != "" {
		mux.Handle("POST /evaluate", telemetry.WrapHTTP("evaluate",
			sidecar.EvaluationHandler(synchronizer, adapterToken, telemetry)))
		mux.Handle("GET /guard-requirements", telemetry.WrapHTTP("guard_requirements",
			sidecar.GuardRequirementsHandler(synchronizer, adapterToken)))
		mux.Handle("POST /approval-permits/claim",
			telemetry.WrapHTTP("approval_claim", sidecar.ApprovalPermitHandler(synchronizer, adapterToken)))
		mux.Handle("POST /approval-permits/recover",
			telemetry.WrapHTTP("approval_recover", sidecar.ApprovalPermitRecoveryHandler(synchronizer, adapterToken)))
		mux.Handle("POST /execution/observed-receipts", telemetry.WrapHTTP("observed_execution_receipt", sidecar.ObservedExecutionReceiptHandler(synchronizer, adapterToken)))
		mux.Handle("POST /execution-receipts",
			telemetry.WrapHTTP("execution_receipt", sidecar.ExecutionReceiptHandler(synchronizer, adapterToken)))
	}
	if operatorToken != "" {
		handler := sidecar.OperatorGapHandler(synchronizer, operatorToken)
		mux.Handle("GET /observations/gaps", handler)
		mux.Handle("GET /observations/gaps/history", handler)
		mux.Handle("POST /observations/gaps/acknowledgements", handler)
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
	if err := telemetry.Run(ctx, "sync", synchronizer.Sync); err != nil && ctx.Err() == nil {
		log.Print("initial configuration sync: ", safeError(err))
	}
	go func() {
		retryTicker := time.NewTicker(15 * time.Second)
		defer retryTicker.Stop()
		for {
			if err := telemetry.Run(ctx, "retry_reports", synchronizer.RetryObservations); err != nil && ctx.Err() == nil {
				log.Print("Observe reports remain queued")
			}
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
			}
		}
	}()
	go func() {
		signalTicker := time.NewTicker(30 * time.Second)
		// Health delivery is independent of decision and report processing.
		defer signalTicker.Stop()
		for {
			if err := telemetry.Run(ctx, "health_signal", synchronizer.ReportSignal); err != nil && ctx.Err() == nil {
				log.Print("sidecar signal could not be delivered")
			}
			select {
			case <-ctx.Done():
				return
			case <-signalTicker.C:
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
			_ = telemetry.Shutdown(shutdown)
			cancel()
			return
		case <-ticker.C:
			if err := telemetry.Run(ctx, "sync", synchronizer.Sync); err != nil && ctx.Err() == nil {
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
