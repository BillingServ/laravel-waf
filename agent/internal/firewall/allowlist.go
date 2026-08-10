package firewall

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
)

const (
	DefaultMetricsIPv4Set = "laravel_waf_metrics_v4"
	DefaultMetricsIPv6Set = "laravel_waf_metrics_v6"
)

// IPSetAllowlist atomically maintains the source ranges that must bypass the
// WAF's kernel DROP rule. Nginx and the metrics handler remain responsible for
// authorizing the actual metrics endpoint.
type IPSetAllowlist struct {
	Runner       CommandRunner
	Executable   string
	IPv4Set      string
	IPv6Set      string
	IPv4Prefixes []netip.Prefix
	IPv6Prefixes []netip.Prefix
	Enabled      bool
	DryRun       bool
	Logger       *log.Logger
}

func NewIPSetAllowlist(
	runner CommandRunner,
	executable, ipv4Set, ipv6Set string,
	allowed []string,
	enabled, dryRun bool,
	logger *log.Logger,
) (*IPSetAllowlist, error) {
	if runner == nil {
		runner = OSCommandRunner{}
	}
	if strings.TrimSpace(executable) == "" {
		return nil, fmt.Errorf("ipset executable is required")
	}
	if !safeSetName.MatchString(ipv4Set) || !safeSetName.MatchString(ipv6Set) || ipv4Set == ipv6Set {
		return nil, fmt.Errorf("invalid metrics allow ipset name")
	}
	if !safeSetName.MatchString(ipv4Set+"_next") || !safeSetName.MatchString(ipv6Set+"_next") {
		return nil, fmt.Errorf("metrics allow ipset name is too long for atomic updates")
	}

	ipv4, ipv6, err := parseAllowedPrefixes(allowed)
	if err != nil {
		return nil, err
	}

	return &IPSetAllowlist{
		Runner:       runner,
		Executable:   executable,
		IPv4Set:      ipv4Set,
		IPv6Set:      ipv6Set,
		IPv4Prefixes: ipv4,
		IPv6Prefixes: ipv6,
		Enabled:      enabled,
		DryRun:       dryRun,
		Logger:       logger,
	}, nil
}

func (a *IPSetAllowlist) Ensure(ctx context.Context) error {
	if !a.Enabled {
		return nil
	}
	if a.DryRun {
		if a.Logger != nil {
			a.Logger.Print("dry-run ipset operation=ensure_metrics_allowlist")
		}

		return nil
	}

	if err := a.replace(ctx, a.IPv4Set, "inet", a.IPv4Prefixes); err != nil {
		return fmt.Errorf("ensure IPv4 metrics source allowlist: %w", err)
	}
	if err := a.replace(ctx, a.IPv6Set, "inet6", a.IPv6Prefixes); err != nil {
		return fmt.Errorf("ensure IPv6 metrics source allowlist: %w", err)
	}

	return nil
}

func (a *IPSetAllowlist) replace(ctx context.Context, set, family string, prefixes []netip.Prefix) error {
	next := set + "_next"
	commands := [][]string{
		{"create", set, "hash:net", "family", family, "-exist"},
		{"create", next, "hash:net", "family", family, "-exist"},
		{"flush", next},
	}
	for _, prefix := range prefixes {
		commands = append(commands, []string{"add", next, prefix.String(), "-exist"})
	}
	commands = append(commands,
		[]string{"swap", next, set},
		[]string{"destroy", next},
	)

	for _, command := range commands {
		if err := a.Runner.Run(ctx, a.Executable, command...); err != nil {
			return fmt.Errorf("ipset %s: %w", command[0], err)
		}
	}

	return nil
}

func parseAllowedPrefixes(values []string) ([]netip.Prefix, []netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		prefix, err := allowedPrefix(value)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid metrics allowed IP or CIDR %q", value)
		}
		for _, expanded := range expandZeroPrefix(prefix) {
			seen[expanded] = struct{}{}
		}
	}

	ipv4 := make([]netip.Prefix, 0, len(seen))
	ipv6 := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, prefix)
		} else {
			ipv6 = append(ipv6, prefix)
		}
	}
	sortPrefixes(ipv4)
	sortPrefixes(ipv6)

	return ipv4, ipv6, nil
}

func allowedPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("invalid prefix")
		}

		return prefix.Masked(), nil
	}

	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address")
	}
	address = address.Unmap()

	return netip.PrefixFrom(address, address.BitLen()), nil
}

func expandZeroPrefix(prefix netip.Prefix) []netip.Prefix {
	if prefix.Bits() != 0 {
		return []netip.Prefix{prefix}
	}
	if prefix.Addr().Is4() {
		return []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
		}
	}

	return []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		if comparison := prefixes[i].Addr().Compare(prefixes[j].Addr()); comparison != 0 {
			return comparison < 0
		}

		return prefixes[i].Bits() < prefixes[j].Bits()
	})
}
