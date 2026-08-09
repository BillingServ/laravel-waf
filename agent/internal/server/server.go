package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
	"github.com/BillingServ/laravel-waf/agent/internal/unixsocket"
)

type Backend interface {
	Ensure(context.Context) error
	Block(context.Context, net.IP, int) error
	Unblock(context.Context, net.IP) error
}

type BlockStore interface {
	RecordBlock(net.IP, int, string) error
	RemoveBlock(net.IP) error
}

type Server struct {
	Socket      string
	SocketGroup string
	Secret      []byte
	MaxTTL      int
	Backend     Backend
	Store       BlockStore
	Metrics     *metrics.Registry
	Logger      *log.Logger
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Backend == nil || s.Metrics == nil {
		return fmt.Errorf("backend and metrics registry are required")
	}

	listener, err := unixsocket.Listen(s.Socket, s.SocketGroup, "agent")
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(s.Socket)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	semaphore := make(chan struct{}, 64)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			if errors.Is(err, syscall.EBADF) {
				return nil
			}

			continue
		}

		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				s.handle(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))

	scanner := bufio.NewScanner(io.LimitReader(connection, 8192))
	scanner.Buffer(make([]byte, 1024), 8192)
	if !scanner.Scan() {
		writeError(connection, "empty decision")
		return
	}

	var decision protocol.Decision
	if err := json.Unmarshal(scanner.Bytes(), &decision); err != nil {
		s.Metrics.Decision("unknown", "invalid_json")
		writeError(connection, "invalid decision")
		return
	}

	if err := decision.Validate(s.MaxTTL); err != nil || !decision.Verify(s.Secret) {
		s.Metrics.Decision(metricAction(decision.Action), "rejected")
		writeError(connection, "decision rejected")
		return
	}

	ip := net.ParseIP(decision.IP)
	if ip == nil {
		s.Metrics.Decision(metricAction(decision.Action), "rejected")
		writeError(connection, "invalid IP")
		return
	}

	operation := "block"
	var backendErr error
	var stateErr error
	operationContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if decision.Action == "block_ip" {
		backendErr = s.Backend.Block(operationContext, ip, decision.TTLSeconds)
		if backendErr == nil && s.Store != nil {
			stateErr = s.Store.RecordBlock(ip, decision.TTLSeconds, decision.Reason)
		}
	} else {
		operation = "unblock"
		backendErr = s.Backend.Unblock(operationContext, ip)
		if backendErr == nil && s.Store != nil {
			stateErr = s.Store.RemoveBlock(ip)
		}
	}

	family := "ipv6"
	if ip.To4() != nil {
		family = "ipv4"
	}

	if backendErr != nil {
		s.Metrics.Decision(decision.Action, "backend_error")
		s.Metrics.Operation(operation, "error", family)
		writeError(connection, "firewall backend error")
		return
	}

	outcome := "accepted"
	if stateErr != nil {
		outcome = "accepted_state_error"
		if s.Logger != nil {
			s.Logger.Printf("block state update failed after successful %s: %v", operation, stateErr)
		}
	}

	s.Metrics.Decision(decision.Action, outcome)
	s.Metrics.Operation(operation, "accepted", family)
	writeOK(connection)
}

func metricAction(action string) string {
	if action == "block_ip" || action == "unblock_ip" {
		return action
	}

	return "unknown"
}

func writeOK(connection net.Conn) {
	_, _ = connection.Write([]byte(`{"ok":true}` + "\n"))
}

func writeError(connection net.Conn, message string) {
	payload, _ := json.Marshal(map[string]any{"ok": false, "error": message})
	_, _ = connection.Write(append(payload, '\n'))
}
