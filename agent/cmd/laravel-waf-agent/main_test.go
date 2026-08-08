package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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
