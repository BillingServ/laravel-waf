package metrics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
	"github.com/BillingServ/laravel-waf/agent/internal/unixsocket"
)

// IngestServer receives fire-and-forget Laravel metric updates on a dedicated
// Unix socket. Keeping this traffic separate prevents observability bursts from
// delaying firewall block decisions on the control socket.
type IngestServer struct {
	Socket      string
	SocketGroup string
	Secret      []byte
	Registry    *Registry
}

func (s *IngestServer) ListenAndServe(ctx context.Context) error {
	if s.Registry == nil {
		return fmt.Errorf("metrics registry is required")
	}

	listener, err := unixsocket.Listen(s.Socket, s.SocketGroup, "metrics ingest")
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
			if ctx.Err() != nil || errors.Is(err, syscall.EBADF) {
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
			s.Registry.MetricEvent("busy")
			_ = connection.Close()
		}
	}
}

func (s *IngestServer) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	reader := bufio.NewReader(io.LimitReader(connection, protocol.MaxMetricEventBytes+1))
	payload, err := reader.ReadBytes('\n')
	if len(payload) == 0 || len(payload) > protocol.MaxMetricEventBytes || (err != nil && !errors.Is(err, io.EOF)) {
		s.Registry.MetricEvent("invalid")
		return
	}

	var event protocol.MetricEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		s.Registry.MetricEvent("invalid_json")
		return
	}
	if err := event.Validate(); err != nil || !event.Verify(s.Secret) {
		s.Registry.MetricEvent("rejected")
		return
	}
	if err := s.Registry.RecordMetric(event); err != nil {
		s.Registry.MetricEvent("rejected_schema")
		return
	}

	s.Registry.MetricEvent("accepted")
}
