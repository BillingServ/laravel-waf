package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type commandCall struct {
	executable string
	args       []string
}

type scriptedRunner struct {
	calls   []commandCall
	results []error
}

func (r *scriptedRunner) Run(_ context.Context, executable string, args ...string) error {
	r.calls = append(r.calls, commandCall{executable: executable, args: append([]string(nil), args...)})
	if len(r.results) == 0 {
		return nil
	}

	result := r.results[0]
	r.results = r.results[1:]

	return result
}

func TestIPTablesEnsureInsertsMissingIPv4AndIPv6Rules(t *testing.T) {
	missing := errors.New("rule does not exist")
	runner := &scriptedRunner{results: []error{missing, nil, missing, nil}}
	manager, err := NewIPTablesRuleManager(
		runner,
		"/usr/sbin/iptables",
		"/usr/sbin/ip6tables",
		"waf_v4",
		"waf_v6",
		true,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}

	expected := []commandCall{
		{executable: "/usr/sbin/iptables", args: []string{"-w", "5", "-C", "INPUT", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/iptables", args: []string{"-w", "5", "-I", "INPUT", "1", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-C", "INPUT", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-I", "INPUT", "1", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
	}
	if !reflect.DeepEqual(expected, runner.calls) {
		t.Fatalf("unexpected commands: %#v", runner.calls)
	}
}

func TestIPTablesEnsureDoesNotDuplicateExistingRules(t *testing.T) {
	runner := &scriptedRunner{}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected two check commands, got %#v", runner.calls)
	}
	for _, call := range runner.calls {
		if len(call.args) < 3 || call.args[2] != "-C" {
			t.Fatalf("expected only rule checks, got %#v", runner.calls)
		}
	}
}

func TestIPTablesEnsureReportsInsertFailure(t *testing.T) {
	missing := errors.New("rule does not exist")
	insertFailure := errors.New("permission denied")
	runner := &scriptedRunner{results: []error{missing, insertFailure}}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err == nil {
		t.Fatal("expected insertion failure")
	}
}

func TestIPTablesDryRunDoesNotExecuteCommands(t *testing.T) {
	runner := &scriptedRunner{}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", true, true, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry-run executed commands: %#v", runner.calls)
	}
}

func TestIPTablesRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewIPTablesRuleManager(nil, "iptables", "ip6tables", "waf;drop", "waf_v6", true, false, nil); err == nil {
		t.Fatal("expected invalid set name to be rejected")
	}
	if _, err := NewIPTablesRuleManager(nil, "", "ip6tables", "waf_v4", "waf_v6", true, false, nil); err == nil {
		t.Fatal("expected missing executable to be rejected")
	}
}
