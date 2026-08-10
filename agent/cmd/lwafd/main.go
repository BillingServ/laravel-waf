package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/blocklist"
	"github.com/BillingServ/laravel-waf/agent/internal/control"
	"github.com/BillingServ/laravel-waf/agent/internal/firewall"
	"github.com/BillingServ/laravel-waf/agent/internal/gate"
	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
	"github.com/BillingServ/laravel-waf/agent/internal/server"
)

const (
	defaultControlSecretFile = "/etc/laravel-waf/agent.secret"
	defaultBlockStateFile    = "/var/lib/laravel-waf/blocks.json"
)

var (
	programName         = "lwafd"
	programVersion      = "dev"
	safeMetricsInstance = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$`)
)

func main() {
	handled, err := runControlCommand(os.Args[1:], os.Stdout, os.Stderr)
	if handled {
		if err == nil || errors.Is(err, flag.ErrHelp) {
			return
		}

		_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		os.Exit(1)
	}

	runDaemon()
}

func runDaemon() {
	var (
		socket           = flag.String("socket", "/run/laravel-waf/agent.sock", "absolute Unix socket path")
		socketGroup      = flag.String("socket-group", "", "optional group name or numeric GID for the Unix socket")
		secretFile       = flag.String("secret-file", "", "optional file containing the one shared WAF secret")
		stateFile        = flag.String("state-file", defaultBlockStateFile, "file storing active block reasons and expiries")
		ipsetPath        = flag.String("ipset", "ipset", "ipset executable")
		iptablesPath     = flag.String("iptables", "iptables", "iptables executable")
		ip6tablesPath    = flag.String("ip6tables", "ip6tables", "ip6tables executable")
		ipv4Set          = flag.String("ipv4-set", "laravel_waf_block_v4", "IPv4 ipset name")
		ipv6Set          = flag.String("ipv6-set", "laravel_waf_block_v6", "IPv6 ipset name")
		blockTCPPorts    = flag.String("block-tcp-ports", "80,443", "comma-separated TCP destination ports blocked for listed IPs")
		maxTTL           = flag.Int("max-ttl", protocol.MaxTTLSeconds, "maximum block TTL in seconds")
		ensureSets       = flag.Bool("ensure-ipsets", true, "create ipsets when the agent starts")
		manageIPTables   = flag.Bool("manage-iptables", true, "attach the expiring ipsets to iptables INPUT rules")
		reconcileEvery   = flag.Duration("firewall-reconcile-interval", 30*time.Second, "interval used to restore firewall rules after a reload; zero disables periodic checks")
		dryRun           = flag.Bool("dry-run", false, "validate requests without modifying ipset or iptables")
		metricsAddr      = flag.String("metrics-address", "127.0.0.1:9919", "metrics listener; empty disables metrics")
		metricsAllowed   = flag.String("metrics-allowed-ips", "", "comma-separated IPs or CIDRs allowed to access metrics and exempt from the WAF kernel DROP rule; loopback is always allowed")
		metricsInstance  = flag.String("metrics-instance", "", "Prometheus instance label; defaults to the operating-system hostname")
		metricsSocket    = flag.String("metrics-ingest-socket", "/run/laravel-waf/metrics.sock", "Unix socket receiving signed Laravel metric events; empty disables ingestion")
		metricsGroup     = flag.String("metrics-ingest-socket-group", "", "optional metrics-ingest socket group; defaults to socket-group")
		gateSocket       = flag.String("gate-socket", "", "optional Unix HTTP socket used by Nginx auth_request")
		gateGroup        = flag.String("gate-socket-group", "", "optional gate socket group; defaults to socket-group")
		gateLimit        = flag.Uint64("gate-threshold", 600, "site-wide requests allowed in each gate window")
		gateClientLimit  = flag.Uint64("gate-client-threshold", gate.DefaultClientThreshold, "unverified requests allowed per client path in each gate window; total client allowance is twice this value; zero disables automatic blocking")
		gateWindow       = flag.Duration("gate-window", time.Minute, "fixed traffic-pressure window")
		gateBlockTTL     = flag.Int("gate-block-ttl", gate.DefaultBlockTTLSeconds, "seconds a gate rate-limit block remains active")
		gateMethods      = flag.String("gate-methods", "GET,HEAD", "comma-separated original methods eligible for a challenge")
		gateBypass       = flag.String("gate-bypass-prefixes", "/_waf/challenge,/_waf/blocked", "comma-separated URI prefixes excluded from the gate counter")
		cookieName       = flag.String("challenge-cookie", "laravel_waf_challenge", "Laravel WAF pass cookie name")
		cookieSecretFile = flag.String("challenge-secret-file", "", "optional gate cookie-secret override; defaults to secret-file")
		gateTokenFile    = flag.String("gate-token-file", "", "optional gate marker-token override; defaults to secret-file")
	)
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		_, _ = fmt.Fprintln(output, "Usage:")
		_, _ = fmt.Fprintf(output, "  %s [daemon options]\n", programName)
		_, _ = fmt.Fprintf(output, "  %s add-ip [options] <ip> <duration>\n", programName)
		_, _ = fmt.Fprintf(output, "  %s remove-ip [options] <ip>\n", programName)
		_, _ = fmt.Fprintf(output, "  %s list-ip [options]\n", programName)
		_, _ = fmt.Fprintln(output, "\nDaemon options:")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := log.New(os.Stdout, programName+" ", log.LstdFlags)
	secret, err := readSecret(*secretFile)
	if err != nil {
		logger.Fatal(err)
	}
	if len(secret) == 0 {
		logger.Print("warning: no HMAC secret configured; rely on Unix socket permissions")
	}
	if *reconcileEvery < 0 {
		logger.Fatal("firewall reconcile interval cannot be negative")
	}
	instance, err := resolveMetricsInstance(*metricsInstance)
	if err != nil {
		logger.Fatal(err)
	}

	blockStore := openBlockStore(*stateFile, logger)
	metricsSources := commaSeparated(*metricsAllowed)

	sets, err := firewall.NewIPSetBackend(
		firewall.OSCommandRunner{},
		*ipsetPath,
		*ipv4Set,
		*ipv6Set,
		*maxTTL,
		*ensureSets,
		*dryRun,
		logger,
	)
	if err != nil {
		logger.Fatal(err)
	}
	metricsAllowlist, err := firewall.NewIPSetAllowlist(
		firewall.OSCommandRunner{},
		*ipsetPath,
		firewall.DefaultMetricsIPv4Set,
		firewall.DefaultMetricsIPv6Set,
		metricsSources,
		*manageIPTables,
		*dryRun,
		logger,
	)
	if err != nil {
		logger.Fatal(err)
	}

	rules, err := firewall.NewIPTablesRuleManager(
		firewall.OSCommandRunner{},
		*iptablesPath,
		*ip6tablesPath,
		*ipv4Set,
		*ipv6Set,
		*blockTCPPorts,
		*manageIPTables,
		*dryRun,
		logger,
	)
	if err != nil {
		logger.Fatal(err)
	}
	if err := rules.UseSourceAllowlist(metricsAllowlist.IPv4Set, metricsAllowlist.IPv6Set); err != nil {
		logger.Fatal(err)
	}

	backend, err := firewall.NewManagedBackend(sets, metricsAllowlist, rules)
	if err != nil {
		logger.Fatal(err)
	}

	if err := backend.Ensure(context.Background()); err != nil {
		logger.Fatal(err)
	}

	registry := metrics.NewRegistry(instance, programVersion)
	decisionServer := &server.Server{
		Socket:      *socket,
		SocketGroup: *socketGroup,
		Secret:      secret,
		MaxTTL:      *maxTTL,
		Backend:     backend,
		Store:       blockStore,
		Metrics:     registry,
		Logger:      logger,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errors := make(chan error, 4)

	if *manageIPTables && !*dryRun && *reconcileEvery > 0 {
		go reconcileFirewallRules(ctx, backend, *reconcileEvery, logger)
	}

	if *metricsAddr != "" {
		metricsHandler, err := metrics.NewHTTPHandler(registry, metricsSources)
		if err != nil {
			logger.Fatal(err)
		}
		metricsServer := &http.Server{
			Addr:              *metricsAddr,
			Handler:           metricsHandler,
			ReadHeaderTimeout: 2 * time.Second,
			IdleTimeout:       5 * time.Second,
			MaxHeaderBytes:    16 * 1024,
		}

		go func() {
			<-ctx.Done()
			_ = metricsServer.Shutdown(context.Background())
		}()

		go func() {
			logger.Printf("metrics listening on %s", *metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errors <- fmt.Errorf("serve metrics: %w", err)
			}
		}()
	}

	if strings.TrimSpace(*metricsSocket) != "" {
		group := *metricsGroup
		if group == "" {
			group = *socketGroup
		}
		logger.Printf("Laravel metrics ingest listening on %s", *metricsSocket)
		go func() {
			errors <- (&metrics.IngestServer{
				Socket:      *metricsSocket,
				SocketGroup: group,
				Secret:      secret,
				Registry:    registry,
			}).ListenAndServe(ctx)
		}()
	}

	if strings.TrimSpace(*gateSocket) != "" {
		if *gateClientLimit > 0 && (*gateBlockTTL < 1 || *gateBlockTTL > *maxTTL) {
			logger.Fatalf("gate block TTL must be between 1 and %d seconds", *maxTTL)
		}
		challengeSecret, err := readSecretOverride(*cookieSecretFile, secret)
		if err != nil {
			logger.Fatal(err)
		}
		gateToken, err := readSecretOverride(*gateTokenFile, secret)
		if err != nil {
			logger.Fatal(err)
		}
		gateHandler, err := gate.NewHandler(gate.Config{
			Threshold:       *gateLimit,
			ClientThreshold: *gateClientLimit,
			Window:          *gateWindow,
			BlockTTLSeconds: *gateBlockTTL,
			CookieName:      *cookieName,
			ChallengeSecret: challengeSecret,
			MarkerToken:     string(gateToken),
			BypassPrefixes:  commaSeparated(*gateBypass),
			Methods:         commaSeparated(*gateMethods),
		}, registry, decisionServer)
		if err != nil {
			logger.Fatal(err)
		}
		decisionServer.Observer = gateHandler
		if blockStore != nil {
			records, err := blockStore.List()
			if err != nil {
				logger.Printf("warning: active blocks could not be loaded into the gate: %v", err)
			} else {
				for _, record := range records {
					gateHandler.ObserveBlock(net.ParseIP(record.IP), time.Unix(record.ExpiresAt, 0))
				}
			}
		}

		group := *gateGroup
		if group == "" {
			group = *socketGroup
		}
		logger.Printf("gate listening on %s", *gateSocket)
		go func() {
			errors <- (&gate.Server{
				Socket:      *gateSocket,
				SocketGroup: group,
				Handler:     gateHandler,
			}).ListenAndServe(ctx)
		}()
	}

	logger.Printf("listening on %s", *socket)
	go func() {
		errors <- decisionServer.ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-errors:
		if err != nil {
			logger.Fatal(err)
		}
	}
}

func runControlCommand(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	if args[0] == "list-ip" || args[0] == "list-ips" {
		return runListCommand(args[1:], stdout, stderr)
	}
	if args[0] != "add-ip" && args[0] != "remove-ip" {
		return false, nil
	}

	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "/run/laravel-waf/agent.sock", "absolute Unix socket path")
	secretFile := flags.String("secret-file", defaultControlSecretFile, "file containing the shared HMAC secret")
	timeout := flags.Duration("timeout", 2*time.Second, "socket request timeout")
	reason := flags.String("reason", "manual", "bounded reason recorded for the decision")
	flags.Usage = func() {
		if command == "add-ip" {
			_, _ = fmt.Fprintf(stderr, "Usage: %s add-ip [options] <ip> <duration>\n\nDuration accepts seconds or Go duration notation such as 15m or 2h.\n\n", programName)
		} else {
			_, _ = fmt.Fprintf(stderr, "Usage: %s remove-ip [options] <ip>\n\n", programName)
		}
		flags.PrintDefaults()
	}

	if err := flags.Parse(args[1:]); err != nil {
		return true, err
	}

	expectedArgs := 1
	if command == "add-ip" {
		expectedArgs = 2
	}
	if flags.NArg() != expectedArgs {
		flags.Usage()

		return true, fmt.Errorf("invalid arguments")
	}

	ip := net.ParseIP(flags.Arg(0))
	if ip == nil {
		return true, fmt.Errorf("invalid IP address %q", flags.Arg(0))
	}

	decision := protocol.Decision{
		Version: protocol.Version,
		IP:      ip.String(),
		Reason:  *reason,
	}
	if command == "add-ip" {
		ttl, err := parseTTL(flags.Arg(1))
		if err != nil {
			return true, err
		}

		decision.Action = "block_ip"
		decision.TTLSeconds = ttl
	} else {
		decision.Action = "unblock_ip"
	}

	secret, err := readSecret(*secretFile)
	if err != nil {
		return true, err
	}

	client := control.Client{
		Socket:  *socket,
		Secret:  secret,
		Timeout: *timeout,
	}
	if err := client.Send(context.Background(), decision); err != nil {
		return true, err
	}

	if command == "add-ip" {
		_, _ = fmt.Fprintf(stdout, "added %s to the block set for %s (reason: %s)\n", decision.IP, (time.Duration(decision.TTLSeconds) * time.Second).String(), decision.Reason)
	} else {
		_, _ = fmt.Fprintf(stdout, "removed %s from the block set\n", decision.IP)
	}

	return true, nil
}

func runListCommand(args []string, stdout, stderr io.Writer) (bool, error) {
	flags := flag.NewFlagSet("list-ip", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateFile := flags.String("state-file", defaultBlockStateFile, "file storing active block reasons and expiries")
	jsonOutput := flags.Bool("json", false, "print block records as JSON")
	flags.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: %s list-ip [options]\n", programName)
		_, _ = fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return true, err
	}
	if flags.NArg() != 0 {
		flags.Usage()

		return true, fmt.Errorf("invalid arguments")
	}

	store, err := blocklist.NewFileStore(*stateFile)
	if err != nil {
		return true, err
	}
	records, err := store.List()
	if err != nil {
		return true, err
	}

	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(records); err != nil {
			return true, fmt.Errorf("encode block list: %w", err)
		}

		return true, nil
	}

	if len(records) == 0 {
		_, _ = fmt.Fprintln(stdout, "no active blocked IPs")

		return true, nil
	}

	writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "IP\tREASON\tEXPIRES IN")
	for _, record := range records {
		_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\n", record.IP, record.Reason, expiresIn(record.ExpiresAt))
	}
	if err := writer.Flush(); err != nil {
		return true, fmt.Errorf("write block list: %w", err)
	}

	return true, nil
}

func expiresIn(expiresAt int64) string {
	remaining := time.Until(time.Unix(expiresAt, 0))
	if remaining <= 0 {
		return "expired"
	}

	seconds := int64(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}

	return (time.Duration(seconds) * time.Second).String()
}

func parseTTL(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("block duration is required")
	}

	seconds, secondsErr := strconv.ParseInt(value, 10, 64)
	if secondsErr != nil {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("invalid block duration %q (use seconds, 15m, or 2h)", value)
		}
		if duration%time.Second != 0 {
			return 0, fmt.Errorf("block duration must use whole seconds")
		}

		seconds = int64(duration / time.Second)
	}

	if seconds < 1 || seconds > protocol.MaxTTLSeconds {
		return 0, fmt.Errorf("block duration must be between 1 and %d seconds", protocol.MaxTTLSeconds)
	}

	return int(seconds), nil
}

func reconcileFirewallRules(ctx context.Context, backend *firewall.ManagedBackend, interval time.Duration, logger *log.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operationContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := backend.EnsurePolicy(operationContext)
			cancel()
			if err != nil && ctx.Err() == nil {
				logger.Printf("firewall rule reconciliation failed: %v", err)
			}
		}
	}
}

func openBlockStore(path string, logger *log.Logger) *blocklist.FileStore {
	store, err := blocklist.NewFileStore(path)
	if err == nil {
		_, err = store.List()
	}
	if err != nil {
		if logger != nil {
			logger.Printf("warning: block state ledger disabled: %v", err)
		}

		return nil
	}

	return store
}

func readSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}

	return []byte(strings.TrimSpace(string(secret))), nil
}

func readSecretOverride(path string, fallback []byte) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return fallback, nil
	}

	return readSecret(path)
}

func resolveMetricsInstance(configured string) (string, error) {
	instance := strings.TrimSpace(configured)
	if instance == "" {
		var err error
		instance, err = os.Hostname()
		if err != nil {
			return "", fmt.Errorf("resolve metrics hostname: %w", err)
		}
	}
	instance = strings.TrimSuffix(strings.TrimSpace(instance), ".")
	if !safeMetricsInstance.MatchString(instance) {
		return "", fmt.Errorf("metrics instance must be a hostname-like value of at most 253 characters")
	}

	return instance, nil
}

func commaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}

	return values
}
