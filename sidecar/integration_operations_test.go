package sidecar

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Setup must never install contracts from unverified configuration or expose them without local authentication.
func TestIntegrationOperationsUseOnlyVerifiedSelectedContracts(t *testing.T) {
	rail := decisionRail("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000031", "guard", nil)
	s := decisionSynchronizer(t, []map[string]any{rail, rail})
	before, _ := json.Marshal(s.state)
	call := func(token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/integration-operations", nil)
		request.Header.Set("Authorization", token)
		response := httptest.NewRecorder()
		IntegrationOperationsHandler(s, "adapter-token").ServeHTTP(response, request)
		return response
	}
	if response := call("Bearer wrong"); response.Code != 401 {
		t.Fatal("unauthenticated setup disclosed contracts")
	}
	response := call("Bearer adapter-token")
	var result integrationOperations
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Operations) != 1 || result.Operations[0].VersionID != decisionOperationID || result.BundleID == "" {
		t.Fatalf("selected contract unavailable: %d %s", response.Code, response.Body.String())
	}
	after, _ := json.Marshal(s.state)
	if string(before) != string(after) {
		t.Fatal("reading setup contracts changed durable state")
	}
	s.mu.Lock()
	s.state.Floor++
	s.mu.Unlock()
	if response := call("Bearer adapter-token"); response.Code != 503 {
		t.Fatal("rollback-floor violation supplied setup contracts")
	}
	conflict := decisionRail("00000000-0000-4000-8000-000000000033", "00000000-0000-4000-8000-000000000034", "guard", nil)
	conflict["operationContract"].(map[string]any)["summary"] = "Different reviewed contract"
	other := decisionSynchronizer(t, []map[string]any{rail, conflict})
	request := httptest.NewRequest(http.MethodGet, "/integration-operations", nil)
	request.Header.Set("Authorization", "Bearer adapter-token")
	response = httptest.NewRecorder()
	IntegrationOperationsHandler(other, "adapter-token").ServeHTTP(response, request)
	if response.Code != 503 {
		t.Fatal("conflicting same-version contracts accepted")
	}
}
