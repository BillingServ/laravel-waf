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
	err    error
}

func (m *fakeRuleManager) Ensure(context.Context) error {
	*m.events = append(*m.events, "rules.ensure")
	return m.err
}

func TestManagedBackendEnsuresRuleBeforeBlock(t *testing.T) {
	events := []string{}
	backend, err := NewManagedBackend(&fakeSetBackend{events: &events}, &fakeRuleManager{events: &events})
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

func TestManagedBackendDoesNotAddIPWhenRuleCannotBeEnsured(t *testing.T) {
	events := []string{}
	backend, err := NewManagedBackend(
		&fakeSetBackend{events: &events},
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
