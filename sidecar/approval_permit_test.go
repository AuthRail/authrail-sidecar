package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type unavailableApprovalTransport struct{ calls int }

func (transport *unavailableApprovalTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("control plane unavailable")
}

func TestApprovalPermitClaimUsesSidecarCredentialOnce(t *testing.T) {
	const actionID = "00000000-0000-4000-8000-000000000001"
	const requestID = "00000000-0000-4000-8000-000000000002"
	const permitID = "00000000-0000-4000-8000-000000000003"
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.URL.Path != "/runtime/deployment/approval-permits/claim" ||
			r.Header.Get("Authorization") != "Bearer deployment-secret" {
			t.Errorf("wrong protected server request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(approvalPermit{PermitID: permitID,
			ActionID: actionID, ExpiresAt: time.Now().Add(time.Minute)})
	}))
	defer server.Close()
	syncer := &Synchronizer{options: Options{ControlPlaneURL: server.URL,
		Token: "deployment-secret", Client: server.Client()}}
	claim := approvalClaim{ApprovalRequestID: requestID, ActionID: actionID,
		InputSHA256: strings.Repeat("a", 64), KeySHA256: strings.Repeat("b", 64),
		Proof: IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "signature"}}
	body, _ := json.Marshal(claim)
	handler := ApprovalPermitHandler(syncer, strings.Repeat("c", 32))
	request := httptest.NewRequest(http.MethodPost, "/approval-permits/claim", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || posts != 0 {
		t.Fatalf("unauthenticated claim reached control plane: %d %d", response.Code, posts)
	}
	request = httptest.NewRequest(http.MethodPost, "/approval-permits/claim", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || posts != 1 {
		t.Fatalf("claim was not forwarded exactly once: %d %d", response.Code, posts)
	}
}

func TestApprovalPermitClaimFailsClosedWhenControlPlaneIsOffline(t *testing.T) {
	transport := &unavailableApprovalTransport{}
	syncer := &Synchronizer{options: Options{ControlPlaneURL: "http://localhost.invalid",
		Token: "deployment-secret", Client: &http.Client{Transport: transport}}}
	claim := approvalClaim{
		ApprovalRequestID: "00000000-0000-4000-8000-000000000002",
		ActionID:          "00000000-0000-4000-8000-000000000001",
		InputSHA256:       strings.Repeat("a", 64),
		KeySHA256:         strings.Repeat("b", 64),
		Proof:             IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "signature"},
	}
	body, _ := json.Marshal(claim)
	request := httptest.NewRequest(http.MethodPost, "/approval-permits/claim", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
	response := httptest.NewRecorder()
	ApprovalPermitHandler(syncer, strings.Repeat("c", 32)).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || transport.calls != 1 {
		t.Fatalf("offline claim was not failed closed exactly once: %d %d", response.Code, transport.calls)
	}
}

func TestApprovalPermitRecoveryReadsOnlyExistingClaim(t *testing.T) {
	const actionID = "00000000-0000-4000-8000-000000000001"
	const requestID = "00000000-0000-4000-8000-000000000002"
	const permitID = "00000000-0000-4000-8000-000000000003"
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.URL.Path != "/runtime/deployment/approval-permits/recover" ||
			r.Header.Get("Authorization") != "Bearer deployment-secret" {
			t.Errorf("recovery did not use the protected read path")
		}
		_ = json.NewEncoder(w).Encode(approvalPermit{PermitID: permitID,
			ActionID: actionID, ExpiresAt: time.Now().Add(time.Minute)})
	}))
	defer server.Close()
	syncer := &Synchronizer{options: Options{ControlPlaneURL: server.URL,
		Token: "deployment-secret", Client: server.Client()}}
	claim := approvalClaim{ApprovalRequestID: requestID, ActionID: actionID,
		InputSHA256: strings.Repeat("a", 64), KeySHA256: strings.Repeat("b", 64),
		Proof: IdentityProof{IssuedAt: 1, ExpiresAt: 2, Signature: "signature"}}
	body, _ := json.Marshal(claim)
	handler := ApprovalPermitRecoveryHandler(syncer, strings.Repeat("c", 32))
	request := httptest.NewRequest(http.MethodPost, "/approval-permits/recover", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || reads != 0 {
		t.Fatalf("unauthenticated recovery reached server: %d %d", response.Code, reads)
	}
	request = httptest.NewRequest(http.MethodPost, "/approval-permits/recover", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 32))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || reads != 1 {
		t.Fatalf("recovery did not use one read: %d %d", response.Code, reads)
	}
}
