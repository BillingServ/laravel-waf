package gate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

type Server struct {
	Socket      string
	SocketGroup string
	Handler     http.Handler
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Handler == nil {
		return fmt.Errorf("gate handler is required")
	}
	if err := prepareSocket(s.Socket); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.Socket)
	if err != nil {
		return fmt.Errorf("listen on gate socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.Socket)

	if err := os.Chmod(s.Socket, 0660); err != nil {
		return fmt.Errorf("set gate socket permissions: %w", err)
	}
	if err := chownSocketGroup(s.Socket, s.SocketGroup); err != nil {
		return err
	}

	httpServer := &http.Server{
		Handler:           s.Handler,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownContext)
	}()

	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}

	return fmt.Errorf("serve gate socket: %w", err)
}

func prepareSocket(socket string) error {
	if socket == "" || !filepath.IsAbs(socket) {
		return fmt.Errorf("gate socket must be an absolute path")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return fmt.Errorf("create gate socket directory: %w", err)
	}

	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect gate socket: %w", err)
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
			return fmt.Errorf("lookup gate socket group: %w", lookupErr)
		}
		gid, err = strconv.Atoi(groupInfo.Gid)
		if err != nil {
			return fmt.Errorf("parse gate socket group ID: %w", err)
		}
	}

	if err := os.Chown(socket, -1, gid); err != nil {
		return fmt.Errorf("set gate socket group: %w", err)
	}

	return nil
}
