package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/unixsocket"
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
	listener, err := unixsocket.Listen(s.Socket, s.SocketGroup, "gate")
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(s.Socket)

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
