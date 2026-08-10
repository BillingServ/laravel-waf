package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	Version       = 1
	MaxTTLSeconds = 86400
)

var safeReason = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

type Decision struct {
	Version    int    `json:"version"`
	Action     string `json:"action"`
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
	Signature  string `json:"signature,omitempty"`
}

func (d Decision) Validate(maxTTL int) error {
	if d.Version != Version {
		return fmt.Errorf("unsupported protocol version")
	}

	if d.Action != "block_ip" && d.Action != "unblock_ip" {
		return fmt.Errorf("unsupported action")
	}

	ip := net.ParseIP(d.IP)
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	if d.Action == "block_ip" {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("local IP addresses cannot be blocked")
		}
		if d.TTLSeconds < 1 || d.TTLSeconds > maxTTL {
			return fmt.Errorf("TTL must be between 1 and %d seconds", maxTTL)
		}
	}

	if !safeReason.MatchString(d.Reason) {
		return fmt.Errorf("invalid reason")
	}

	return nil
}

func (d Decision) Canonical() string {
	reason := base64.RawURLEncoding.EncodeToString([]byte(d.Reason))

	return fmt.Sprintf("%d\n%s\n%s\n%d\n%s", d.Version, d.Action, d.IP, d.TTLSeconds, reason)
}

func (d Decision) Verify(secret []byte) bool {
	if len(secret) == 0 {
		return true
	}

	signature, err := hex.DecodeString(strings.TrimSpace(d.Signature))
	if err != nil {
		return false
	}

	return hmac.Equal(signature, d.signature(secret))
}

// Sign sets the HMAC signature used by authenticated agent sockets. An empty
// secret leaves the signature empty for agents secured only by socket
// permissions.
func (d *Decision) Sign(secret []byte) {
	d.Signature = ""
	if len(secret) > 0 {
		d.Signature = hex.EncodeToString(d.signature(secret))
	}
}

func (d Decision) signature(secret []byte) []byte {
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte(d.Canonical()))

	return digest.Sum(nil)
}
