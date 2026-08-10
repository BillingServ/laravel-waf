package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPHandlerAllowsConfiguredCIDR(t *testing.T) {
	registry := NewRegistry()
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

func TestHTTPHandlerAllowsConfiguredExactIP(t *testing.T) {
	handler, err := NewHTTPHandler(NewRegistry(), []string{"192.0.2.10"})
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
	handler, err := NewHTTPHandler(NewRegistry(), nil)
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
	handler, err := NewHTTPHandler(NewRegistry(), []string{"192.0.2.0/24"})
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
	if _, err := NewHTTPHandler(NewRegistry(), []string{"192.0.2.0/99"}); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}
