package firewall

import (
	"context"
	"reflect"
	"testing"
)

func TestIPSetAllowlistAtomicallyReplacesMetricsSources(t *testing.T) {
	runner := &recordingRunner{}
	allowlist, err := NewIPSetAllowlist(
		runner,
		"/usr/sbin/ipset",
		"waf_metrics_v4",
		"waf_metrics_v6",
		[]string{"100.64.0.0/10", "2001:db8::10"},
		true,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("create metrics source allowlist: %v", err)
	}

	if err := allowlist.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure metrics source allowlist: %v", err)
	}

	expected := [][]string{
		{"create", "waf_metrics_v4", "hash:net", "family", "inet", "-exist"},
		{"create", "waf_metrics_v4_next", "hash:net", "family", "inet", "-exist"},
		{"flush", "waf_metrics_v4_next"},
		{"add", "waf_metrics_v4_next", "100.64.0.0/10", "-exist"},
		{"swap", "waf_metrics_v4_next", "waf_metrics_v4"},
		{"destroy", "waf_metrics_v4_next"},
		{"create", "waf_metrics_v6", "hash:net", "family", "inet6", "-exist"},
		{"create", "waf_metrics_v6_next", "hash:net", "family", "inet6", "-exist"},
		{"flush", "waf_metrics_v6_next"},
		{"add", "waf_metrics_v6_next", "2001:db8::10/128", "-exist"},
		{"swap", "waf_metrics_v6_next", "waf_metrics_v6"},
		{"destroy", "waf_metrics_v6_next"},
	}
	if !reflect.DeepEqual(expected, runner.args) {
		t.Fatalf("unexpected ipset commands: %#v", runner.args)
	}
}

func TestIPSetAllowlistRejectsInvalidMetricsSource(t *testing.T) {
	if _, err := NewIPSetAllowlist(
		nil,
		"ipset",
		"waf_metrics_v4",
		"waf_metrics_v6",
		[]string{"not-an-ip"},
		true,
		false,
		nil,
	); err == nil {
		t.Fatal("expected invalid metrics source to be rejected")
	}
}
