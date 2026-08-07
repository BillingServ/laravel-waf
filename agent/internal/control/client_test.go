package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

func TestClientSendsSignedDecision(t *testing.T) {
	secret := []byte("test-secret")
	socket, serverErrors := serveOnce(t, func(decision protocol.Decision) (string, error) {
		if decision.Action != "block_ip" || decision.IP != "203.0.113.10" || decision.TTLSeconds != 900 {
			return "", fmt.Errorf("unexpected decision: %#v", decision)
		}
		if !decision.Verify(secret) {
			return "", fmt.Errorf("decision signature did not verify")
		}

		return `{"ok":true}`, nil
	})

	client := Client{Socket: socket, Secret: secret, Timeout: time.Second}
	err := client.Send(context.Background(), protocol.Decision{
		Version:    protocol.Version,
		Action:     "block_ip",
		IP:         "203.0.113.10",
		TTLSeconds: 900,
		Reason:     "manual",
	})
	if err != nil {
		t.Fatalf("send decision: %v", err)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestClientReturnsAgentRejection(t *testing.T) {
	socket, serverErrors := serveOnce(t, func(protocol.Decision) (string, error) {
		return `{"ok":false,"error":"decision rejected"}`, nil
	})

	client := Client{Socket: socket, Timeout: time.Second}
	err := client.Send(context.Background(), protocol.Decision{
		Version: protocol.Version,
		Action:  "unblock_ip",
		IP:      "2001:db8::10",
		Reason:  "manual",
	})
	if err == nil || !strings.Contains(err.Error(), "decision rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func serveOnce(t *testing.T, handler func(protocol.Decision) (string, error)) (string, <-chan error) {
	t.Helper()

	directory, err := os.MkdirTemp("/tmp", "waf-control-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	socket := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on test socket: %v", err)
	}

	errors := make(chan error, 1)
	go func() {
		defer listener.Close()

		connection, err := listener.Accept()
		if err != nil {
			errors <- fmt.Errorf("accept test connection: %w", err)
			return
		}
		defer connection.Close()

		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			errors <- fmt.Errorf("read test decision: %w", err)
			return
		}

		var decision protocol.Decision
		if err := json.Unmarshal(line, &decision); err != nil {
			errors <- fmt.Errorf("decode test decision: %w", err)
			return
		}

		response, err := handler(decision)
		if err != nil {
			errors <- err
			return
		}
		if _, err := fmt.Fprintf(connection, "%s\n", response); err != nil {
			errors <- fmt.Errorf("write test response: %w", err)
			return
		}

		errors <- nil
	}()

	return socket, errors
}
