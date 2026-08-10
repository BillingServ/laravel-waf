package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPHandlerAllowsConfiguredCIDR(t *testing.T) {
	registry := NewRegistry("test.example", "test")
	registry.Decision("block_ip", "accepted")
	handler, err := NewHTTPHandler(registry, []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("create metrics handler: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://agent/metrics", nil)
	request.RemoteAddr = "192.0.2.25:43120"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "laravel_waf_agent_decisions_total") {
		t.Fatal("expected agent metrics response")
	}
}

func TestRegistryExportsHostIdentityAndZeroIngestOutcomes(t *testing.T) {
	registry := NewRegistry("dev.bserv.dev", "abc123")
	registry.Decision("block_ip", "accepted")
	registry.Operation("block", "accepted", "ipv4")
	registry.Gate("allowed")

	body := registry.render()
	for _, expected := range []string{
		`laravel_waf_info{instance="dev.bserv.dev",application="lwafd",version="abc123"} 1`,
		`laravel_waf_agent_decisions_total{instance="dev.bserv.dev",action="block_ip",outcome="accepted"} 1`,
		`laravel_waf_agent_firewall_operations_total{instance="dev.bserv.dev",family="ipv4",operation="block",outcome="accepted"} 1`,
		`laravel_waf_agent_gate_requests_total{instance="dev.bserv.dev",outcome="allowed"} 1`,
		`laravel_waf_agent_metric_events_total{instance="dev.bserv.dev",outcome="accepted"} 0`,
		`laravel_waf_agent_metric_events_total{instance="dev.bserv.dev",outcome="rejected"} 0`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q from metrics response: %s", expected, body)
		}
	}
}

func TestHTTPHandlerAllowsConfiguredExactIP(t *testing.T) {
	handler, err := NewHTTPHandler(NewRegistry("test.example", "test"), []string{"192.0.2.10"})
	if err != nil {
		t.Fatalf("create metrics handler: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://agent/healthz", nil)
	request.RemoteAddr = "192.0.2.10:43120"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("unexpected health response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestHTTPHandlerAlwaysAllowsLoopback(t *testing.T) {
	handler, err := NewHTTPHandler(NewRegistry("test.example", "test"), nil)
	if err != nil {
		t.Fatalf("create metrics handler: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://agent/metrics", nil)
	request.RemoteAddr = "127.0.0.1:43120"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected loopback status 200, got %d", response.Code)
	}
}

func TestHTTPHandlerHidesEndpointsFromDeniedClients(t *testing.T) {
	handler, err := NewHTTPHandler(NewRegistry("test.example", "test"), []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("create metrics handler: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://agent/metrics", nil)
	request.RemoteAddr = "203.0.113.20:43120"
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected denied status 404, got %d", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("expected an empty denied response, got %q", response.Body.String())
	}
}

func TestHTTPHandlerRejectsInvalidAllowedRange(t *testing.T) {
	if _, err := NewHTTPHandler(NewRegistry("test.example", "test"), []string{"192.0.2.0/99"}); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}
