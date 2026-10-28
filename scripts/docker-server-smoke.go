//go:build ignore

// Drives advisory call/result retention through the Docker sidecar and real
// server services. The callback is an isolated fixture, never a provider effect.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	authrail "github.com/AuthRail/authrail-sdk-go"
)

func main() {
	keyBytes, err := os.ReadFile(os.Getenv("AUTHRAIL_EXECUTOR_PRIVATE_KEY_FILE"))
	must(err)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic("missing fixture private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	must(err)
	client, err := authrail.NewClient(authrail.Config{
		SidecarURL: os.Getenv("AUTHRAIL_SIDECAR_URL"), AdapterToken: os.Getenv("AUTHRAIL_ADAPTER_TOKEN"),
		OrganisationID: os.Getenv("AUTHRAIL_ORGANISATION_ID"), DeploymentID: os.Getenv("AUTHRAIL_DEPLOYMENT_ID"),
		ExecutorPrivateKey: parsed.(ed25519.PrivateKey),
	})
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, completed, err := authrail.Observe(ctx, client, authrail.Operation{
		VersionID: os.Getenv("AUTHRAIL_OPERATION_VERSION_ID"), ActionKey: setting("AUTHRAIL_SMOKE_ACTION_KEY", "go-slice5-observe"),
		PrincipalID: "isolated-staff", SessionID: "isolated-session",
		PrincipalSource: "application_session", ResourceSource: "not_applicable",
	}, map[string]any{"amount": 80}, func(context.Context) (map[string]any, error) { return map[string]any{"accepted": true}, nil })
	must(err)
	if result["accepted"] != true {
		panic("callback result changed")
	}
	observation := <-completed
	must(observation.CallError)
	must(observation.ResultError)
	recording := setting("AUTHRAIL_SMOKE_RECORDING_STATUS", "retained")
	if recording != "retained" && recording != "queued" {
		panic("unsupported fixture recording expectation")
	}
	if observation.CallDecision == nil || observation.ResultDecision == nil || observation.CallDecision.RecordingStatus != recording || observation.ResultDecision.RecordingStatus != recording {
		panic("unexpected call/result recording state")
	}
	if recording == "queued" && (observation.CallDecision.ActionID != "" || observation.ResultDecision.ActionID != "") {
		panic("queued report invented retained Action identity")
	}
}

func setting(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
