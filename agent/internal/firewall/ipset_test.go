package firewall

import (
	"context"
	"net"
	"reflect"
	"testing"
)

type recordingRunner struct {
	executable string
	args       [][]string
}

func (r *recordingRunner) Run(_ context.Context, executable string, args ...string) error {
	r.executable = executable
	r.args = append(r.args, append([]string(nil), args...))

	return nil
}

func TestBlockUsesSeparateIPv4SetAndArgumentArray(t *testing.T) {
	runner := &recordingRunner{}
	backend, err := NewIPSetBackend(runner, "/usr/sbin/ipset", "waf_v4", "waf_v6", 3600, false, false, nil)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Block(context.Background(), net.ParseIP("203.0.113.10"), 900); err != nil {
		t.Fatalf("block IP: %v", err)
	}

	if runner.executable != "/usr/sbin/ipset" {
		t.Fatalf("unexpected executable: %s", runner.executable)
	}

	expected := [][]string{{"add", "waf_v4", "203.0.113.10", "timeout", "900", "-exist"}}
	if !reflect.DeepEqual(expected, runner.args) {
		t.Fatalf("unexpected command arguments: %#v", runner.args)
	}
}

func TestBlockUsesIPv6Set(t *testing.T) {
	runner := &recordingRunner{}
	backend, err := NewIPSetBackend(runner, "ipset", "waf_v4", "waf_v6", 3600, false, false, nil)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Block(context.Background(), net.ParseIP("2001:db8::10"), 900); err != nil {
		t.Fatalf("block IP: %v", err)
	}

	expected := [][]string{{"add", "waf_v6", "2001:db8::10", "timeout", "900", "-exist"}}
	if !reflect.DeepEqual(expected, runner.args) {
		t.Fatalf("unexpected command arguments: %#v", runner.args)
	}
}

func TestUnblockIsIdempotent(t *testing.T) {
	runner := &recordingRunner{}
	backend, err := NewIPSetBackend(runner, "ipset", "waf_v4", "waf_v6", 3600, false, false, nil)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}

	if err := backend.Unblock(context.Background(), net.ParseIP("203.0.113.10")); err != nil {
		t.Fatalf("unblock IP: %v", err)
	}

	expected := [][]string{{"del", "waf_v4", "203.0.113.10", "-exist"}}
	if !reflect.DeepEqual(expected, runner.args) {
		t.Fatalf("unexpected command arguments: %#v", runner.args)
	}
}

func TestInvalidSetNameIsRejected(t *testing.T) {
	if _, err := NewIPSetBackend(nil, "ipset", "waf;drop", "waf_v6", 3600, false, false, nil); err == nil {
		t.Fatal("expected invalid set name to be rejected")
	}
}
