package metrics

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

func TestIngestServerRecordsSignedLaravelMetrics(t *testing.T) {
	registry := NewRegistry("test.example", "test")
	secret := []byte("test-secret")
	server := &IngestServer{Secret: secret, Registry: registry}
	event := protocol.MetricEvent{
		Version:   protocol.Version,
		Action:    protocol.MetricAction,
		Operation: protocol.MetricIncrement,
		Name:      "findings",
		Labels: map[string]string{
			"category": "xss",
			"rule":     "script_tag",
			"action":   "reject",
			"route":    "admin.login",
		},
		Value: 1,
	}
	event.Sign(secret)

	sendMetricEvent(t, server, event)

	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, `laravel_waf_findings_total{instance="test.example",category="xss",rule="script_tag",action="reject",route="admin.login"} 1`) {
		t.Fatalf("Laravel metric was not exposed: %s", body)
	}
	if !strings.Contains(body, `laravel_waf_agent_metric_events_total{instance="test.example",outcome="accepted"} 1`) {
		t.Fatalf("accepted ingest was not exposed: %s", body)
	}
}

func TestIngestServerRejectsInvalidSignature(t *testing.T) {
	registry := NewRegistry("test.example", "test")
	server := &IngestServer{Secret: []byte("correct-secret"), Registry: registry}
	event := protocol.MetricEvent{
		Version:   protocol.Version,
		Action:    protocol.MetricAction,
		Operation: protocol.MetricIncrement,
		Name:      "errors",
		Labels:    map[string]string{"component": "rate_limiter"},
		Value:     1,
	}
	event.Sign([]byte("wrong-secret"))

	sendMetricEvent(t, server, event)

	body := registry.render()
	if strings.Contains(body, `laravel_waf_errors_total{instance="test.example",component="rate_limiter"}`) {
		t.Fatalf("rejected metric was exposed: %s", body)
	}
	if !strings.Contains(body, `laravel_waf_agent_metric_events_total{instance="test.example",outcome="rejected"} 1`) {
		t.Fatalf("rejected ingest was not exposed: %s", body)
	}
}

func TestRegistryRendersPrometheusHistogram(t *testing.T) {
	registry := NewRegistry("test.example", "test")
	event := protocol.MetricEvent{
		Version:   protocol.Version,
		Action:    protocol.MetricAction,
		Operation: protocol.MetricObserve,
		Name:      "evaluation_duration_seconds",
		Labels:    map[string]string{},
		Value:     25_000_000,
	}
	if err := registry.RecordMetric(event); err != nil {
		t.Fatalf("record histogram: %v", err)
	}

	body := registry.render()
	for _, expected := range []string{
		`laravel_waf_evaluation_duration_seconds_bucket{instance="test.example",le="0.025"} 1`,
		`laravel_waf_evaluation_duration_seconds_bucket{instance="test.example",le="+Inf"} 1`,
		`laravel_waf_evaluation_duration_seconds_sum{instance="test.example"} 0.025`,
		`laravel_waf_evaluation_duration_seconds_count{instance="test.example"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q from histogram: %s", expected, body)
		}
	}
}

func TestRegistryRejectsAnInvalidMetricEventWhenCalledDirectly(t *testing.T) {
	registry := NewRegistry("test.example", "test")
	event := protocol.MetricEvent{
		Version:   protocol.Version,
		Action:    protocol.MetricAction,
		Operation: protocol.MetricIncrement,
		Name:      "errors",
		Labels:    map[string]string{"component": "rate_limiter"},
		Value:     -1,
	}

	if err := registry.RecordMetric(event); err == nil {
		t.Fatal("expected invalid counter value to be rejected")
	}
	if strings.Contains(registry.render(), `laravel_waf_errors_total{instance="test.example",component="rate_limiter"}`) {
		t.Fatal("invalid metric was recorded")
	}
}

func sendMetricEvent(t *testing.T, server *IngestServer, event protocol.MetricEvent) {
	t.Helper()

	serverConnection, clientConnection := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handle(serverConnection)
		close(done)
	}()

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	if _, err := fmt.Fprintf(clientConnection, "%s\n", payload); err != nil {
		t.Fatalf("send event: %v", err)
	}
	_ = clientConnection.Close()
	<-done
}
