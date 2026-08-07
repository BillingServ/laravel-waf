package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

const maxResponseBytes = 8192

type Client struct {
	Socket  string
	Secret  []byte
	Timeout time.Duration
}

type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func (c Client) Send(ctx context.Context, decision protocol.Decision) error {
	if c.Socket == "" || !filepath.IsAbs(c.Socket) {
		return fmt.Errorf("agent socket must be an absolute path")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("agent timeout must be positive")
	}
	if err := decision.Validate(protocol.MaxTTLSeconds); err != nil {
		return fmt.Errorf("invalid decision: %w", err)
	}

	decision.Sign(c.Secret)
	payload, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("encode decision: %w", err)
	}
	if len(payload) > maxResponseBytes-1 {
		return fmt.Errorf("decision is too large")
	}

	dialer := net.Dialer{Timeout: c.Timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("connect to agent: %w", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(c.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set agent deadline: %w", err)
	}

	if _, err := connection.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("send decision: %w", err)
	}

	line, err := bufio.NewReader(io.LimitReader(connection, maxResponseBytes+1)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return fmt.Errorf("read agent response: %w", err)
	}
	if len(line) > maxResponseBytes {
		return fmt.Errorf("agent response is too large")
	}

	var result response
	if err := json.Unmarshal(line, &result); err != nil {
		return fmt.Errorf("decode agent response: %w", err)
	}
	if !result.OK {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "decision rejected"
		}

		return fmt.Errorf("agent rejected decision: %s", message)
	}

	return nil
}
