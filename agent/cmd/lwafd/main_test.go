package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BillingServ/laravel-waf/agent/internal/blocklist"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

func TestRunAddIPCommand(t *testing.T) {
	socket, decisions := receiveDecision(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	handled, err := runControlCommand([]string{
		"add-ip",
		"--socket", socket,
		"--secret-file=",
		"--reason", "manual_review",
		"203.0.113.10",
		"15m",
	}, stdout, stderr)
	if err != nil {
		t.Fatalf("run add command: %v (stderr: %s)", err, stderr.String())
	}
	if !handled {
		t.Fatal("expected add command to be handled")
	}

	result := <-decisions
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.decision.Action != "block_ip" || result.decision.IP != "203.0.113.10" || result.decision.TTLSeconds != 900 || result.decision.Reason != "manual_review" {
		t.Fatalf("unexpected decision: %#v", result.decision)
	}
	if !strings.Contains(stdout.String(), "15m0s") {
		t.Fatalf("unexpected command output: %q", stdout.String())
	}
}

func TestRunListIPCommandShowsReason(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "blocks.json")
	store, err := blocklist.NewFileStore(stateFile)
	if err != nil {
		t.Fatalf("create block store: %v", err)
	}
	if err := store.RecordBlock(net.ParseIP("203.0.113.10"), 900, "rule_sql_injection"); err != nil {
		t.Fatalf("record block: %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	handled, err := runControlCommand([]string{
		"list-ip",
		"--state-file", stateFile,
	}, stdout, stderr)
	if err != nil {
		t.Fatalf("run list command: %v (stderr: %s)", err, stderr.String())
	}
	if !handled {
		t.Fatal("expected list command to be handled")
	}
	if !strings.Contains(stdout.String(), "203.0.113.10") || !strings.Contains(stdout.String(), "rule_sql_injection") {
		t.Fatalf("expected IP and reason in output: %q", stdout.String())
	}
}

func TestOpenBlockStoreTreatsTheAuditLedgerAsOptional(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := log.New(logs, "", 0)

	if store := openBlockStore("relative/blocks.json", logger); store != nil {
		t.Fatal("expected an invalid state path to disable the audit ledger")
	}
	if !strings.Contains(logs.String(), "block state ledger disabled") {
		t.Fatalf("expected a visible warning, got %q", logs.String())
	}

	stateFile := filepath.Join(t.TempDir(), "blocks.json")
	if store := openBlockStore(stateFile, logger); store == nil {
		t.Fatal("expected a valid state path to keep the audit ledger enabled")
	}
}

func TestRunRemoveIPCommand(t *testing.T) {
	socket, decisions := receiveDecision(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	handled, err := runControlCommand([]string{
		"remove-ip",
		"--socket", socket,
		"--secret-file=",
		"2001:db8::10",
	}, stdout, stderr)
	if err != nil {
		t.Fatalf("run remove command: %v (stderr: %s)", err, stderr.String())
	}
	if !handled {
		t.Fatal("expected remove command to be handled")
	}

	result := <-decisions
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.decision.Action != "unblock_ip" || result.decision.IP != "2001:db8::10" || result.decision.TTLSeconds != 0 {
		t.Fatalf("unexpected decision: %#v", result.decision)
	}
	if !strings.Contains(stdout.String(), "removed 2001:db8::10") {
		t.Fatalf("unexpected command output: %q", stdout.String())
	}
}

func TestParseTTL(t *testing.T) {
	tests := map[string]int{
		"900":   900,
		"15m":   900,
		"2h":    7200,
		"24h":   86400,
		"1m30s": 90,
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual, err := parseTTL(input)
			if err != nil {
				t.Fatalf("parse TTL: %v", err)
			}
			if actual != expected {
				t.Fatalf("expected %d seconds, got %d", expected, actual)
			}
		})
	}
}

func TestParseTTLRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", "0", "-1s", "500ms", "25h", "tomorrow"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseTTL(input); err == nil {
				t.Fatalf("expected %q to be rejected", input)
			}
		})
	}
}

func TestResolveMetricsInstanceUsesConfiguredHostname(t *testing.T) {
	actual, err := resolveMetricsInstance(" dev.bserv.dev. ")
	if err != nil {
		t.Fatalf("resolve metrics instance: %v", err)
	}
	if actual != "dev.bserv.dev" {
		t.Fatalf("expected normalized hostname, got %q", actual)
	}
}

func TestResolveMetricsInstanceUsesOperatingSystemHostnameByDefault(t *testing.T) {
	expected, err := os.Hostname()
	if err != nil {
		t.Fatalf("read operating-system hostname: %v", err)
	}
	expected = strings.TrimSuffix(strings.TrimSpace(expected), ".")

	actual, err := resolveMetricsInstance("")
	if err != nil {
		t.Fatalf("resolve default metrics instance: %v", err)
	}
	if actual != expected {
		t.Fatalf("expected operating-system hostname %q, got %q", expected, actual)
	}
}

func TestResolveMetricsInstanceRejectsUnsafeValue(t *testing.T) {
	if _, err := resolveMetricsInstance("dev server\ninvalid"); err == nil {
		t.Fatal("expected an unsafe metrics instance to be rejected")
	}
}

func TestReadSecretOverrideDefaultsToTheSharedSecret(t *testing.T) {
	shared := []byte("one-shared-secret-with-at-least-32-bytes")

	actual, err := readSecretOverride("", shared)
	if err != nil {
		t.Fatalf("read shared secret: %v", err)
	}
	if string(actual) != string(shared) {
		t.Fatalf("expected shared secret, got %q", string(actual))
	}
}

func TestReadSecretOverridePreservesLegacyOverrideFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.secret")
	if err := os.WriteFile(path, []byte("legacy-secret-with-at-least-32-bytes\n"), 0o600); err != nil {
		t.Fatalf("write legacy secret: %v", err)
	}

	actual, err := readSecretOverride(path, []byte("shared-secret-with-at-least-32-bytes"))
	if err != nil {
		t.Fatalf("read legacy override: %v", err)
	}
	if string(actual) != "legacy-secret-with-at-least-32-bytes" {
		t.Fatalf("unexpected legacy override %q", string(actual))
	}
}

type decisionResult struct {
	decision protocol.Decision
	err      error
}

func receiveDecision(t *testing.T) (string, <-chan decisionResult) {
	t.Helper()

	directory, err := os.MkdirTemp("/tmp", "waf-command-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	socket := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	results := make(chan decisionResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			results <- decisionResult{err: fmt.Errorf("accept test connection: %w", err)}
			return
		}
		defer connection.Close()

		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			results <- decisionResult{err: fmt.Errorf("read test decision: %w", err)}
			return
		}

		var decision protocol.Decision
		if err := json.Unmarshal(line, &decision); err != nil {
			results <- decisionResult{err: fmt.Errorf("decode test decision: %w", err)}
			return
		}
		if _, err := fmt.Fprintln(connection, `{"ok":true}`); err != nil {
			results <- decisionResult{err: fmt.Errorf("write test response: %w", err)}
			return
		}

		results <- decisionResult{decision: decision}
	}()

	return socket, results
}
