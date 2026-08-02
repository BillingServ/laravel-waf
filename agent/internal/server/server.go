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
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

type Backend interface {
	Ensure(context.Context) error
	Block(context.Context, net.IP, int) error
	Unblock(context.Context, net.IP) error
}

type Server struct {
	Socket      string
	SocketGroup string
	Secret      []byte
	MaxTTL      int
	Backend     Backend
	Metrics     *metrics.Registry
	Logger      *log.Logger
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Backend == nil || s.Metrics == nil {
		return fmt.Errorf("backend and metrics registry are required")
	}

	if err := prepareSocket(s.Socket); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.Socket)
	if err != nil {
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.Socket)

	if err := os.Chmod(s.Socket, 0660); err != nil {
		return fmt.Errorf("set agent socket permissions: %w", err)
	}
	if err := chownSocketGroup(s.Socket, s.SocketGroup); err != nil {
		return err
	}

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
	var err error
	operationContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if decision.Action == "block_ip" {
		err = s.Backend.Block(operationContext, ip, decision.TTLSeconds)
	} else {
		operation = "unblock"
		err = s.Backend.Unblock(operationContext, ip)
	}

	family := "ipv6"
	if ip.To4() != nil {
		family = "ipv4"
	}

	if err != nil {
		s.Metrics.Decision(decision.Action, "backend_error")
		s.Metrics.Operation(operation, "error", family)
		writeError(connection, "firewall backend error")
		return
	}

	s.Metrics.Decision(decision.Action, "accepted")
	s.Metrics.Operation(operation, "accepted", family)
	writeOK(connection)
}

func metricAction(action string) string {
	if action == "block_ip" || action == "unblock_ip" {
		return action
	}

	return "unknown"
}

func prepareSocket(socket string) error {
	if socket == "" || !filepath.IsAbs(socket) {
		return fmt.Errorf("agent socket must be an absolute path")
	}

	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return fmt.Errorf("create agent socket directory: %w", err)
	}

	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect agent socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %q", socket)
	}

	return os.Remove(socket)
}

func chownSocketGroup(socket, group string) error {
	if group == "" {
		return nil
	}

	gid, err := strconv.Atoi(group)
	if err != nil {
		groupInfo, lookupErr := user.LookupGroup(group)
		if lookupErr != nil {
			return fmt.Errorf("lookup socket group: %w", lookupErr)
		}

		gid, err = strconv.Atoi(groupInfo.Gid)
		if err != nil {
			return fmt.Errorf("parse socket group ID: %w", err)
		}
	}

	if err := os.Chown(socket, -1, gid); err != nil {
		return fmt.Errorf("set agent socket group: %w", err)
	}

	return nil
}

func writeOK(connection net.Conn) {
	_, _ = connection.Write([]byte(`{"ok":true}` + "\n"))
}

func writeError(connection net.Conn, message string) {
	payload, _ := json.Marshal(map[string]any{"ok": false, "error": message})
	_, _ = connection.Write(append(payload, '\n'))
}
