package firewall

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
)

// IPTablesRuleManager keeps one static INPUT rule attached to each expiring
// ipset. Individual IP addresses and their expiry remain entirely in ipset.
type IPTablesRuleManager struct {
	Runner         CommandRunner
	IPv4Executable string
	IPv6Executable string
	IPv4Set        string
	IPv6Set        string
	TCPPorts       string
	Enabled        bool
	DryRun         bool
	Logger         *log.Logger

	mu sync.Mutex
}

func NewIPTablesRuleManager(
	runner CommandRunner,
	ipv4Executable, ipv6Executable, ipv4Set, ipv6Set, tcpPorts string,
	enabled, dryRun bool,
	logger *log.Logger,
) (*IPTablesRuleManager, error) {
	if runner == nil {
		runner = OSCommandRunner{}
	}

	if !safeSetName.MatchString(ipv4Set) || !safeSetName.MatchString(ipv6Set) {
		return nil, fmt.Errorf("invalid ipset name")
	}

	if enabled && (strings.TrimSpace(ipv4Executable) == "" || strings.TrimSpace(ipv6Executable) == "") {
		return nil, fmt.Errorf("iptables and ip6tables executables are required")
	}

	normalizedPorts, err := normalizeTCPPorts(tcpPorts)
	if err != nil {
		return nil, err
	}

	return &IPTablesRuleManager{
		Runner:         runner,
		IPv4Executable: ipv4Executable,
		IPv6Executable: ipv6Executable,
		IPv4Set:        ipv4Set,
		IPv6Set:        ipv6Set,
		TCPPorts:       normalizedPorts,
		Enabled:        enabled,
		DryRun:         dryRun,
		Logger:         logger,
	}, nil
}

// Ensure attaches each set to INPUT. The rule itself is permanent; ipset
// expires individual members in-kernel according to their own timeout.
func (m *IPTablesRuleManager) Ensure(ctx context.Context) error {
	if !m.Enabled {
		return nil
	}

	if m.DryRun {
		if m.Logger != nil {
			m.Logger.Print("dry-run iptables operation=ensure")
		}

		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureRule(ctx, m.IPv4Executable, m.IPv4Set); err != nil {
		return fmt.Errorf("ensure IPv4 iptables rule: %w", err)
	}

	if err := m.ensureRule(ctx, m.IPv6Executable, m.IPv6Set); err != nil {
		return fmt.Errorf("ensure IPv6 iptables rule: %w", err)
	}

	return nil
}

func (m *IPTablesRuleManager) ensureRule(ctx context.Context, executable, set string) error {
	if err := m.removeLegacyAllTrafficRule(ctx, executable, set); err != nil {
		return err
	}

	rule := []string{
		"INPUT",
		"-p", "tcp",
		"-m", "multiport", "--dports", m.TCPPorts,
		"-m", "set", "--match-set", set, "src",
		"-j", "DROP",
	}
	check := append([]string{"-w", "5", "-C"}, rule...)
	if err := m.Runner.Run(ctx, executable, check...); err == nil {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Explicitly insert at position one so the block runs before broad ACCEPT
	// rules created by the host firewall policy.
	insert := append([]string{"-w", "5", "-I", "INPUT", "1"}, rule[1:]...)
	if err := m.Runner.Run(ctx, executable, insert...); err != nil {
		return err
	}

	if m.Logger != nil {
		m.Logger.Printf("attached firewall rule to ipset %s", set)
	}

	return nil
}

func (m *IPTablesRuleManager) removeLegacyAllTrafficRule(ctx context.Context, executable, set string) error {
	legacyRule := []string{"INPUT", "-m", "set", "--match-set", set, "src", "-j", "DROP"}
	check := append([]string{"-w", "5", "-C"}, legacyRule...)
	if err := m.Runner.Run(ctx, executable, check...); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}

		return nil
	}

	remove := append([]string{"-w", "5", "-D"}, legacyRule...)
	if err := m.Runner.Run(ctx, executable, remove...); err != nil {
		return fmt.Errorf("remove legacy all-traffic rule: %w", err)
	}

	if m.Logger != nil {
		m.Logger.Printf("removed legacy all-traffic firewall rule for ipset %s", set)
	}

	return nil
}

func normalizeTCPPorts(value string) (string, error) {
	parts := strings.Split(value, ",")
	ports := make([]string, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid TCP block port %q", part)
		}
		if _, exists := seen[port]; exists {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, strconv.Itoa(port))
	}

	if len(ports) == 0 || len(ports) > 15 {
		return "", fmt.Errorf("TCP block ports must contain between 1 and 15 unique ports")
	}

	return strings.Join(ports, ","), nil
}
