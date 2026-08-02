package firewall

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
)

var safeSetName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,31}$`)

type CommandRunner interface {
	Run(ctx context.Context, executable string, args ...string) error
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, executable string, args ...string) error {
	return exec.CommandContext(ctx, executable, args...).Run()
}

type IPSetBackend struct {
	Runner     CommandRunner
	Executable string
	IPv4Set    string
	IPv6Set    string
	MaxTTL     int
	EnsureSets bool
	DryRun     bool
	Logger     *log.Logger
}

func NewIPSetBackend(runner CommandRunner, executable, ipv4Set, ipv6Set string, maxTTL int, ensureSets, dryRun bool, logger *log.Logger) (*IPSetBackend, error) {
	if runner == nil {
		runner = OSCommandRunner{}
	}

	if !safeSetName.MatchString(ipv4Set) || !safeSetName.MatchString(ipv6Set) {
		return nil, fmt.Errorf("invalid ipset name")
	}

	if maxTTL < 1 || maxTTL > 86400 {
		return nil, fmt.Errorf("max TTL must be between 1 and 86400 seconds")
	}

	return &IPSetBackend{
		Runner:     runner,
		Executable: executable,
		IPv4Set:    ipv4Set,
		IPv6Set:    ipv6Set,
		MaxTTL:     maxTTL,
		EnsureSets: ensureSets,
		DryRun:     dryRun,
		Logger:     logger,
	}, nil
}

func (b *IPSetBackend) Ensure(ctx context.Context) error {
	if !b.EnsureSets {
		return nil
	}

	if err := b.create(ctx, b.IPv4Set, "inet"); err != nil {
		return fmt.Errorf("create IPv4 ipset: %w", err)
	}

	if err := b.create(ctx, b.IPv6Set, "inet6"); err != nil {
		return fmt.Errorf("create IPv6 ipset: %w", err)
	}

	return nil
}

func (b *IPSetBackend) Block(ctx context.Context, ip net.IP, ttl int) error {
	set, normalized, err := b.setForIP(ip)
	if err != nil {
		return err
	}

	ttl = max(1, min(ttl, b.MaxTTL))
	args := []string{"add", set, normalized, "timeout", strconv.Itoa(ttl), "-exist"}

	return b.run(ctx, "block", args...)
}

func (b *IPSetBackend) Unblock(ctx context.Context, ip net.IP) error {
	set, normalized, err := b.setForIP(ip)
	if err != nil {
		return err
	}

	return b.run(ctx, "unblock", "del", set, normalized)
}

func (b *IPSetBackend) create(ctx context.Context, set, family string) error {
	return b.run(ctx, "ensure", "create", set, "hash:ip", "family", family, "timeout", strconv.Itoa(b.MaxTTL), "-exist")
}

func (b *IPSetBackend) run(ctx context.Context, operation string, args ...string) error {
	if b.DryRun {
		if b.Logger != nil {
			b.Logger.Printf("dry-run ipset operation=%s", operation)
		}

		return nil
	}

	if err := b.Runner.Run(ctx, b.Executable, args...); err != nil {
		return fmt.Errorf("ipset %s: %w", operation, err)
	}

	return nil
}

func (b *IPSetBackend) setForIP(ip net.IP) (string, string, error) {
	if ip == nil {
		return "", "", fmt.Errorf("nil IP address")
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return b.IPv4Set, ipv4.String(), nil
	}

	if ipv6 := ip.To16(); ipv6 != nil {
		return b.IPv6Set, ipv6.String(), nil
	}

	return "", "", fmt.Errorf("invalid IP address")
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}
