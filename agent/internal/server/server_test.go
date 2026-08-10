package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

type recordingBackend struct {
	blockedIP   net.IP
	blockedTTL  int
	unblockedIP net.IP
}

func (b *recordingBackend) Ensure(context.Context) error { return nil }

func (b *recordingBackend) Block(_ context.Context, ip net.IP, ttl int) error {
	b.blockedIP = append(net.IP(nil), ip...)
	b.blockedTTL = ttl

	return nil
}

func (b *recordingBackend) Unblock(_ context.Context, ip net.IP) error {
	b.unblockedIP = append(net.IP(nil), ip...)

	return nil
}

type recordingStore struct {
	ip      net.IP
	ttl     int
	reason  string
	removed net.IP
}

func (s *recordingStore) RecordBlock(ip net.IP, ttl int, reason string) error {
	s.ip = append(net.IP(nil), ip...)
	s.ttl = ttl
	s.reason = reason

	return nil
}

func (s *recordingStore) RemoveBlock(ip net.IP) error {
	s.removed = append(net.IP(nil), ip...)

	return nil
}

type failingStore struct{}

type recordingObserver struct {
	blockedIP net.IP
	expiresAt time.Time
}

func (o *recordingObserver) ObserveBlock(ip net.IP, expiresAt time.Time) {
	o.blockedIP = append(net.IP(nil), ip...)
	o.expiresAt = expiresAt
}

func (*recordingObserver) ObserveUnblock(net.IP) {}

func (failingStore) RecordBlock(net.IP, int, string) error {
	return errors.New("state unavailable")
}

func (failingStore) RemoveBlock(net.IP) error {
	return errors.New("state unavailable")
}

func TestHandleRecordsAcceptedBlockReason(t *testing.T) {
	backend := &recordingBackend{}
	store := &recordingStore{}
	observer := &recordingObserver{}
	service := &Server{
		MaxTTL:   protocol.MaxTTLSeconds,
		Backend:  backend,
		Store:    store,
		Metrics:  metrics.NewRegistry(),
		Observer: observer,
	}

	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	go service.handle(serverConnection)

	decision := protocol.Decision{
		Version:    protocol.Version,
		Action:     "block_ip",
		IP:         "203.0.113.10",
		TTLSeconds: 900,
		Reason:     "rule_sql_injection",
	}
	if _, err := fmt.Fprintf(clientConnection, "%s\n", mustJSON(decision)); err != nil {
		t.Fatalf("send decision: %v", err)
	}

	response, err := bufio.NewReader(clientConnection).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(response, &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["ok"] != true {
		t.Fatalf("unexpected response: %s", response)
	}
	if backend.blockedIP.String() != "203.0.113.10" || backend.blockedTTL != 900 {
		t.Fatalf("unexpected backend call: %#v", backend)
	}
	if store.ip.String() != "203.0.113.10" || store.ttl != 900 || store.reason != "rule_sql_injection" {
		t.Fatalf("unexpected block record: %#v", store)
	}
	if observer.blockedIP.String() != "203.0.113.10" || time.Until(observer.expiresAt) <= 0 {
		t.Fatalf("unexpected block observation: %#v", observer)
	}
}

func TestLocalBlockUsesTheDecisionFirewallAndAuditPath(t *testing.T) {
	backend := &recordingBackend{}
	store := &recordingStore{}
	service := &Server{
		MaxTTL:  protocol.MaxTTLSeconds,
		Backend: backend,
		Store:   store,
		Metrics: metrics.NewRegistry(),
	}

	if err := service.Block(context.Background(), net.ParseIP("203.0.113.20"), 900, "gate_rate_limit"); err != nil {
		t.Fatalf("apply local block: %v", err)
	}
	if backend.blockedIP.String() != "203.0.113.20" || backend.blockedTTL != 900 {
		t.Fatalf("unexpected backend call: %#v", backend)
	}
	if store.ip.String() != "203.0.113.20" || store.ttl != 900 || store.reason != "gate_rate_limit" {
		t.Fatalf("unexpected block record: %#v", store)
	}
}

func TestHandleAcceptsFirewallOperationWhenAuditStoreFails(t *testing.T) {
	tests := []protocol.Decision{
		{
			Version:    protocol.Version,
			Action:     "block_ip",
			IP:         "203.0.113.11",
			TTLSeconds: 900,
			Reason:     "rule_xss",
		},
		{
			Version: protocol.Version,
			Action:  "unblock_ip",
			IP:      "203.0.113.12",
			Reason:  "manual",
		},
	}

	for _, decision := range tests {
		t.Run(decision.Action, func(t *testing.T) {
			backend := &recordingBackend{}
			registry := metrics.NewRegistry()
			service := &Server{
				MaxTTL:  protocol.MaxTTLSeconds,
				Backend: backend,
				Store:   failingStore{},
				Metrics: registry,
			}

			serverConnection, clientConnection := net.Pipe()
			defer clientConnection.Close()
			go service.handle(serverConnection)

			if _, err := fmt.Fprintf(clientConnection, "%s\n", mustJSON(decision)); err != nil {
				t.Fatalf("send decision: %v", err)
			}

			response, err := bufio.NewReader(clientConnection).ReadBytes('\n')
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			var payload map[string]any
			if err := json.Unmarshal(response, &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload["ok"] != true {
				t.Fatalf("firewall operation was reported as failed: %s", response)
			}

			if decision.Action == "block_ip" && backend.blockedIP.String() != decision.IP {
				t.Fatalf("block was not applied: %#v", backend)
			}
			if decision.Action == "unblock_ip" && backend.unblockedIP.String() != decision.IP {
				t.Fatalf("unblock was not applied: %#v", backend)
			}

			metricsResponse := httptest.NewRecorder()
			registry.Handler().ServeHTTP(metricsResponse, httptest.NewRequest("GET", "/metrics", nil))
			if !strings.Contains(metricsResponse.Body.String(), `outcome="accepted_state_error"`) {
				t.Fatalf("state failure was not observable in metrics: %s", metricsResponse.Body.String())
			}
		})
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return encoded
}
