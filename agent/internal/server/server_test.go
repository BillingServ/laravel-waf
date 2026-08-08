package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

type recordingBackend struct {
	blockedIP  net.IP
	blockedTTL int
}

func (b *recordingBackend) Ensure(context.Context) error { return nil }

func (b *recordingBackend) Block(_ context.Context, ip net.IP, ttl int) error {
	b.blockedIP = append(net.IP(nil), ip...)
	b.blockedTTL = ttl

	return nil
}

func (b *recordingBackend) Unblock(context.Context, net.IP) error { return nil }

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

func TestHandleRecordsAcceptedBlockReason(t *testing.T) {
	backend := &recordingBackend{}
	store := &recordingStore{}
	service := &Server{
		MaxTTL:  protocol.MaxTTLSeconds,
		Backend: backend,
		Store:   store,
		Metrics: metrics.NewRegistry(),
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
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return encoded
}
