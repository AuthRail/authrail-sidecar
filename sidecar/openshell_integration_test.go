package sidecar

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This crosses the real Node SDK and sidecar HTTP boundary. The control-plane
// retention fixture is not evidence of PostgreSQL or OpenShell containment.
// Risk: sandbox input, replay, denial, or unavailable retention must not run an effect.
func TestOpenShellProtectedExecutorWithNodeAndRealSidecar(t *testing.T) {
	if os.Getenv("AUTHRAIL_OPENSHELL_INTEGRATION") != "1" {
		t.Skip("explicit cross-repository Node integration opt-in required")
	}
	policy := decisionRail("00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013", "policy", []map[string]any{
		{"id": "small", "when": decisionCondition("lte", 100), "outcome": "allow"},
		{"id": "large", "when": decisionCondition("gt", 100), "outcome": "deny"},
	})
	policy["operationContract"].(map[string]any)["requiredCoverage"] = []string{"tool_call", "tool_result"}
	syncer := decisionSynchronizerMode(t, []map[string]any{policy}, "enforce")
	const action = "00000000-0000-4000-8000-000000000020"
	var mu sync.Mutex
	offline := false
	seen := map[string]bool{}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if offline {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer fixture-deployment" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/runtime/deployment/observations":
			var body struct {
				Report struct {
					Phase string `json:"phase"`
				} `json:"report"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := r.Header.Get("Idempotency-Key") + ":" + body.Report.Phase
			replayed := seen[key]
			seen[key] = true
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"actionId": action,
				"certificateId": "00000000-0000-4000-8000-000000000021", "replayed": replayed})
		case "/runtime/deployment/execution-receipts":
			var body struct {
				Event string `json:"event"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			state := "succeeded"
			if body.Event == "started" {
				state = "executing"
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"receiptId": "00000000-0000-4000-8000-000000000022", "state": state, "replayed": false})
		default:
			w.WriteHeader(404)
		}
	}))
	defer control.Close()
	syncer.options.ControlPlaneURL, syncer.options.Token, syncer.options.Client = control.URL, "fixture-deployment", control.Client()
	const token = "abcdefghijklmnopqrstuvwxyz012345"
	bypassProbeHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fixture/bypass-check", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bypassProbeHits++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"sidecarProbeAlive": true})
	})
	mux.HandleFunc("POST /fixture/offline", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		offline = true
		mu.Unlock()
		w.WriteHeader(204)
	})
	mux.Handle("/evaluate", EvaluationHandler(syncer, token))
	mux.Handle("/execution-receipts", ExecutionReceiptHandler(syncer, token))
	local := httptest.NewServer(mux)
	defer local.Close()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := filepath.Abs("../..")
	config, _ := json.Marshal(map[string]any{"sidecarUrl": local.URL, "adapterToken": token,
		"organisationId": organisationID, "deploymentId": deploymentID,
		"executorPrivateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	script := "authrail-sidecar/integrations/openshell/verify-boundary.mjs"
	if os.Getenv("AUTHRAIL_OPENSHELL_GATEWAY_MANIFEST") != "" {
		script = "authrail-sidecar/integrations/openshell/validation/verify-sandbox.mjs"
	}
	command := exec.Command("node", filepath.Join(root, script))
	command.Env = append(os.Environ(), "AUTHRAIL_FIXTURE_CONFIG="+string(config), "AUTHRAIL_FIXTURE_NOW="+syncer.options.Now().Format("2006-01-02T15:04:05Z"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Node protected executor failed: %v\n%s", err, output)
	}
	if os.Getenv("AUTHRAIL_OPENSHELL_GATEWAY_MANIFEST") != "" {
		mu.Lock()
		hits := bypassProbeHits
		mu.Unlock()
		if hits != 1 {
			t.Fatalf("sidecar bypass probe reached handler %d times; only the host positive control may reach it", hits)
		}
	}
	t.Log(strings.TrimSpace(string(output)))
}
