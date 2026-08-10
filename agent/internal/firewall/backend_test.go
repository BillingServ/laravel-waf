package firewall

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeSetBackend struct {
	events *[]string
}

func (b *fakeSetBackend) Ensure(context.Context) error {
	*b.events = append(*b.events, "sets.ensure")
	return nil
}

func (b *fakeSetBackend) Block(context.Context, net.IP, int) error {
	*b.events = append(*b.events, "sets.block")
	return nil
}

func (b *fakeSetBackend) Unblock(context.Context, net.IP) error {
	*b.events = append(*b.events, "sets.unblock")
	return nil
}

type fakeRuleManager struct {
	events *[]string
	event  string
	err    error
}

func (m *fakeRuleManager) Ensure(context.Context) error {
	event := m.event
	if event == "" {
		event = "rules.ensure"
	}
	*m.events = append(*m.events, event)
	return m.err
}

func TestManagedBackendEnsuresRuleBeforeBlock(t *testing.T) {
	events := []string{}
	backend, err := NewManagedBackend(&fakeSetBackend{events: &events}, nil, &fakeRuleManager{events: &events})
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Block(context.Background(), net.ParseIP("203.0.113.10"), 60); err != nil {
		t.Fatalf("block IP: %v", err)
	}

	if len(events) != 2 || events[0] != "rules.ensure" || events[1] != "sets.block" {
		t.Fatalf("unexpected operation order: %#v", events)
	}
}

func TestManagedBackendEnsuresAllowlistBeforeFirewallRules(t *testing.T) {
	events := []string{}
	backend, err := NewManagedBackend(
		&fakeSetBackend{events: &events},
		&fakeRuleManager{events: &events, event: "allowlist.ensure"},
		&fakeRuleManager{events: &events, event: "firewall.ensure"},
	)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure backend: %v", err)
	}

	expected := []string{"sets.ensure", "allowlist.ensure", "firewall.ensure"}
	if len(events) != len(expected) {
		t.Fatalf("unexpected operations: %#v", events)
	}
	for index := range expected {
		if events[index] != expected[index] {
			t.Fatalf("allowlist was not installed before firewall rules: %#v", events)
		}
	}
}

func TestManagedBackendDoesNotAddIPWhenRuleCannotBeEnsured(t *testing.T) {
	events := []string{}
	backend, err := NewManagedBackend(
		&fakeSetBackend{events: &events},
		nil,
		&fakeRuleManager{events: &events, err: errors.New("iptables failed")},
	)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Block(context.Background(), net.ParseIP("203.0.113.10"), 60); err == nil {
		t.Fatal("expected rule failure")
	}

	if len(events) != 1 || events[0] != "rules.ensure" {
		t.Fatalf("unexpected operations after rule failure: %#v", events)
	}
}
