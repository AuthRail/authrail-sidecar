package sidecar

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func dataPlanRail(sourceID string) map[string]any {
	rail := decisionRail("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000031", "data", nil)
	rail["sourceContextVersionId"] = sourceID
	rail["sourceContextContract"] = map[string]any{
		"formatVersion": 1, "provider": "stripe", "lookup": "invoice.retrieve",
		"providerAccountId": "acct_12345678", "queryField": map[string]any{"root": "arguments", "path": []string{"invoiceId"}},
		"factKey": "invoiceStatus", "resultField": "status", "maxAgeSeconds": 60, "timeoutMs": 1000, "failure": "unavailable"}
	return rail
}

// Plan discovery must not disclose configuration without the local adapter credential or mutate state.
func TestDataRequirementsAuthenticationAndReadOnlyState(t *testing.T) {
	rail := dataPlanRail("00000000-0000-4000-8000-000000000030")
	s := decisionSynchronizer(t, []map[string]any{rail})
	before, _ := json.Marshal(s.state)
	for _, test := range []struct {
		query, token string
		status       int
	}{
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call", "", 401},
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call", "Bearer wrong", 401},
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call", "Bearer adapter-token", 200},
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call&phase=tool_result", "Bearer adapter-token", 400},
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call&extra=1", "Bearer adapter-token", 400},
		{"?operationVersionId=" + decisionOperationID + "&phase=tool_call&bad=%", "Bearer adapter-token", 400},
	} {
		request := httptest.NewRequest(http.MethodGet, "/data-requirements"+test.query, nil)
		request.Header.Set("Authorization", test.token)
		response := httptest.NewRecorder()
		DataRequirementsHandler(s, "adapter-token").ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("query %q returned %d", test.query, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("plan response may be cached")
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/data-requirements?operationVersionId="+decisionOperationID+"&phase=tool_call", nil)
	request.Header.Add("Authorization", "Bearer adapter-token")
	request.Header.Add("Authorization", "Bearer adapter-token")
	response := httptest.NewRecorder()
	DataRequirementsHandler(s, "adapter-token").ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("duplicate authorization accepted")
	}
	after, _ := json.Marshal(s.state)
	if string(before) != string(after) {
		t.Fatal("plan discovery changed sidecar state")
	}
	if _, err := os.Stat(s.options.StateFile); !os.IsNotExist(err) {
		t.Fatal("plan discovery wrote persistent state")
	}
}

// Only selected exact Operation/phase sources may reach readers, with stable deduplication and ordering.
func TestDataPlanSelectsExactSources(t *testing.T) {
	first := dataPlanRail("00000000-0000-4000-8000-000000000030")
	second := dataPlanRail("00000000-0000-4000-8000-000000000020")
	s := decisionSynchronizer(t, []map[string]any{first, second, first})
	plan := s.dataPlan(decisionOperationID, "tool_call")
	if plan.Coverage != "evaluated" || len(plan.Requirements) != 2 || plan.Requirements[0].SourceVersionID != second["sourceContextVersionId"] || plan.Requirements[1].SourceVersionID != first["sourceContextVersionId"] {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	var got map[string]any
	_ = json.Unmarshal(plan.Requirements[1].Contract, &got)
	want, _ := json.Marshal(first["sourceContextContract"])
	var expected map[string]any
	_ = json.Unmarshal(want, &expected)
	if !reflect.DeepEqual(got, expected) {
		t.Fatal("plan changed exact signed source contract")
	}
	for _, query := range [][2]string{{decisionOperationID, "tool_result"}, {"00000000-0000-4000-8000-000000000099", "tool_call"}} {
		plan = s.dataPlan(query[0], query[1])
		if plan.Coverage != "uncovered" || len(plan.Requirements) != 0 {
			t.Fatal("unselected source leaked into plan")
		}
	}
	conflict := dataPlanRail(first["sourceContextVersionId"].(string))
	conflict["sourceContextContract"].(map[string]any)["maxAgeSeconds"] = 61
	plan = decisionSynchronizer(t, []map[string]any{first, conflict}).dataPlan(decisionOperationID, "tool_call")
	if plan.Coverage != "unavailable" || len(plan.Requirements) != 0 {
		t.Fatal("conflicting source versions accepted")
	}
}

// Stale, rolled-back, invalid or oversized configuration cannot install readers.
func TestDataPlanFailsClosed(t *testing.T) {
	rail := dataPlanRail("00000000-0000-4000-8000-000000000030")
	for _, kind := range []string{"expired", "floor", "pins", "legacy", "unknown field"} {
		item := dataPlanRail(rail["sourceContextVersionId"].(string))
		if kind == "legacy" {
			item["sourceContextContract"].(map[string]any)["formatVersion"] = 2
		}
		if kind == "unknown field" {
			item["sourceContextContract"].(map[string]any)["endpoint"] = "https://unreviewed.example"
		}
		s := decisionSynchronizer(t, []map[string]any{item})
		if kind == "expired" {
			now := s.options.Now()
			s.options.Now = func() time.Time { return now.Add(2 * time.Hour) }
		}
		if kind == "floor" {
			s.state.Floor = 2
		}
		if kind == "pins" {
			s.options.TrustedPins = map[string]struct{}{}
		}
		plan := s.dataPlan(decisionOperationID, "tool_call")
		if plan.Coverage != "unavailable" || len(plan.Requirements) != 0 {
			t.Fatalf("%s source was available", kind)
		}
	}
	rails := []map[string]any{}
	for i := 0; i < 33; i++ {
		rails = append(rails, dataPlanRail(fmt.Sprintf("00000000-0000-4000-8000-%012d", i)))
	}
	plan := decisionSynchronizer(t, rails).dataPlan(decisionOperationID, "tool_call")
	if plan.Coverage != "unavailable" || len(plan.Requirements) != 0 {
		t.Fatal("oversized plan accepted")
	}
}

// Supported descriptor families retain their exact contracts; a descriptor is not an automatic extractor.
func TestDataPlanSupportedContractFamilies(t *testing.T) {
	for _, kind := range []string{"quickbooks", "customer_api", "database", "mcp", "sdk", "extraction"} {
		rail := dataPlanRail("00000000-0000-4000-8000-000000000030")
		contract := rail["sourceContextContract"].(map[string]any)
		if kind == "quickbooks" {
			contract["formatVersion"], contract["provider"], contract["lookup"] = 3, "quickbooks", "invoice.read"
			contract["providerAccountId"], contract["resultField"] = "realm_1", "Balance"
		} else {
			contract["formatVersion"], contract["kind"] = 4, kind
			delete(contract, "provider")
			delete(contract, "providerAccountId")
			delete(contract, "resultField")
			contract["sourceIdentity"], contract["accountBoundary"], contract["lookup"] = "billing-service", "tenant_1", "invoice.read"
			contract["resultPath"], contract["valueType"] = []string{"balance"}, "number"
			if kind == "extraction" {
				contract["formatVersion"] = 5
				contract["modelId"], contract["modelConfigSha256"], contract["promptVersion"] = "legacy-model", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "reviewed-v1"
				contract["maxInputBytes"], contract["maxOutputBytes"] = 1024, 1024
			}
		}
		plan := decisionSynchronizer(t, []map[string]any{rail}).dataPlan(decisionOperationID, "tool_call")
		if plan.Coverage != "evaluated" || len(plan.Requirements) != 1 {
			t.Fatalf("supported %s descriptor unavailable", kind)
		}
	}
}
