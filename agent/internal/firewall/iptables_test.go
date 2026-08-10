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
	runner := &scriptedRunner{results: []error{missing, missing, missing, nil, missing, missing, missing, nil}}
	manager, err := NewIPTablesRuleManager(
		runner,
		"/usr/sbin/iptables",
		"/usr/sbin/ip6tables",
		"waf_v4",
		"waf_v6",
		"80,443",
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
		{executable: "/usr/sbin/iptables", args: []string{"-w", "5", "-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/iptables", args: []string{"-w", "5", "-C", "INPUT", "!", "-i", "lo", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/iptables", args: []string{"-w", "5", "-I", "INPUT", "1", "!", "-i", "lo", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-C", "INPUT", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-C", "INPUT", "!", "-i", "lo", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
		{executable: "/usr/sbin/ip6tables", args: []string{"-w", "5", "-I", "INPUT", "1", "!", "-i", "lo", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}},
	}
	if !reflect.DeepEqual(expected, runner.calls) {
		t.Fatalf("unexpected commands: %#v", runner.calls)
	}
}

func TestIPTablesEnsureDoesNotDuplicateExistingRules(t *testing.T) {
	missing := errors.New("rule does not exist")
	runner := &scriptedRunner{results: []error{missing, missing, nil, missing, missing, nil}}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,443", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}

	if len(runner.calls) != 6 {
		t.Fatalf("expected six check commands, got %#v", runner.calls)
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
	runner := &scriptedRunner{results: []error{missing, missing, missing, insertFailure}}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,443", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err == nil {
		t.Fatal("expected insertion failure")
	}
}

func TestIPTablesDryRunDoesNotExecuteCommands(t *testing.T) {
	runner := &scriptedRunner{}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,443", true, true, nil)
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
	if _, err := NewIPTablesRuleManager(nil, "iptables", "ip6tables", "waf;drop", "waf_v6", "80,443", true, false, nil); err == nil {
		t.Fatal("expected invalid set name to be rejected")
	}
	if _, err := NewIPTablesRuleManager(nil, "", "ip6tables", "waf_v4", "waf_v6", "80,443", true, false, nil); err == nil {
		t.Fatal("expected missing executable to be rejected")
	}
	if _, err := NewIPTablesRuleManager(nil, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,invalid", true, false, nil); err == nil {
		t.Fatal("expected invalid TCP port to be rejected")
	}
}

func TestIPTablesEnsureRemovesLegacyAllTrafficRules(t *testing.T) {
	missing := errors.New("rule does not exist")
	runner := &scriptedRunner{results: []error{nil, nil, missing, missing, nil, nil, nil, missing, missing, nil}}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,443", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}

	expectedDelete := []string{"-w", "5", "-D", "INPUT", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}
	if !reflect.DeepEqual(expectedDelete, runner.calls[1].args) {
		t.Fatalf("legacy IPv4 rule was not removed: %#v", runner.calls)
	}
	expectedIPv6Delete := []string{"-w", "5", "-D", "INPUT", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}
	if !reflect.DeepEqual(expectedIPv6Delete, runner.calls[6].args) {
		t.Fatalf("legacy IPv6 rule was not removed: %#v", runner.calls)
	}
}

func TestIPTablesEnsureReplacesLoopbackUnsafeRules(t *testing.T) {
	missing := errors.New("rule does not exist")
	runner := &scriptedRunner{results: []error{missing, nil, nil, missing, nil, missing, nil, nil, missing, nil}}
	manager, err := NewIPTablesRuleManager(runner, "iptables", "ip6tables", "waf_v4", "waf_v6", "80,443", true, false, nil)
	if err != nil {
		t.Fatalf("create rule manager: %v", err)
	}

	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure rules: %v", err)
	}

	expectedIPv4Delete := []string{"-w", "5", "-D", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v4", "src", "-j", "DROP"}
	if !reflect.DeepEqual(expectedIPv4Delete, runner.calls[2].args) {
		t.Fatalf("unsafe IPv4 rule was not removed: %#v", runner.calls)
	}
	expectedIPv6Delete := []string{"-w", "5", "-D", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "set", "--match-set", "waf_v6", "src", "-j", "DROP"}
	if !reflect.DeepEqual(expectedIPv6Delete, runner.calls[7].args) {
		t.Fatalf("unsafe IPv6 rule was not removed: %#v", runner.calls)
	}
}

func TestNormalizeTCPPorts(t *testing.T) {
	ports, err := normalizeTCPPorts("443, 80,443")
	if err != nil {
		t.Fatalf("normalize ports: %v", err)
	}
	if ports != "443,80" {
		t.Fatalf("unexpected normalized ports: %s", ports)
	}
}
