package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/firewall"
	"github.com/BillingServ/laravel-waf/agent/internal/gate"
	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/server"
)

func main() {
	var (
		socket           = flag.String("socket", "/run/laravel-waf/agent.sock", "absolute Unix socket path")
		socketGroup      = flag.String("socket-group", "", "optional group name or numeric GID for the Unix socket")
		secretFile       = flag.String("secret-file", "", "optional file containing the shared HMAC secret")
		ipsetPath        = flag.String("ipset", "ipset", "ipset executable")
		ipv4Set          = flag.String("ipv4-set", "laravel_waf_block_v4", "IPv4 ipset name")
		ipv6Set          = flag.String("ipv6-set", "laravel_waf_block_v6", "IPv6 ipset name")
		maxTTL           = flag.Int("max-ttl", 86400, "maximum block TTL in seconds")
		ensureSets       = flag.Bool("ensure-ipsets", true, "create ipsets when the agent starts")
		dryRun           = flag.Bool("dry-run", false, "validate requests without executing ipset")
		metricsAddr      = flag.String("metrics-address", "127.0.0.1:9919", "local metrics listener; empty disables metrics")
		gateSocket       = flag.String("gate-socket", "", "optional Unix HTTP socket used by Nginx auth_request")
		gateGroup        = flag.String("gate-socket-group", "", "optional gate socket group; defaults to socket-group")
		gateLimit        = flag.Uint64("gate-threshold", 600, "site-wide requests allowed in each gate window")
		gateWindow       = flag.Duration("gate-window", time.Minute, "fixed traffic-pressure window")
		gateMethods      = flag.String("gate-methods", "GET,HEAD", "comma-separated original methods eligible for a challenge")
		gateBypass       = flag.String("gate-bypass-prefixes", "/_waf/challenge,/_waf/metrics,/_waf/blocked", "comma-separated URI prefixes excluded from the gate counter")
		cookieName       = flag.String("challenge-cookie", "laravel_waf_challenge", "Laravel WAF pass cookie name")
		cookieSecretFile = flag.String("challenge-secret-file", "", "file containing LARAVEL_WAF_CHALLENGE_COOKIE_SECRET for gate pass validation")
		gateTokenFile    = flag.String("gate-token-file", "", "file containing LARAVEL_WAF_AGENT_GATE_TOKEN for authenticated challenge markers")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "laravel-waf-agent ", log.LstdFlags)
	secret, err := readSecret(*secretFile)
	if err != nil {
		logger.Fatal(err)
	}
	if len(secret) == 0 {
		logger.Print("warning: no HMAC secret configured; rely on Unix socket permissions")
	}

	backend, err := firewall.NewIPSetBackend(
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

	if err := backend.Ensure(context.Background()); err != nil {
		logger.Fatal(err)
	}

	registry := metrics.NewRegistry()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errors := make(chan error, 2)

	if *metricsAddr != "" {
		metricsServer := &http.Server{
			Addr:              *metricsAddr,
			Handler:           metricsMux(registry),
			ReadHeaderTimeout: 2 * time.Second,
		}

		go func() {
			<-ctx.Done()
			_ = metricsServer.Shutdown(context.Background())
		}()

		go func() {
			logger.Printf("metrics listening on %s", *metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("metrics server stopped: %v", err)
			}
		}()
	}

	if strings.TrimSpace(*gateSocket) != "" {
		challengeSecret, err := readSecret(*cookieSecretFile)
		if err != nil {
			logger.Fatal(err)
		}
		gateToken, err := readSecret(*gateTokenFile)
		if err != nil {
			logger.Fatal(err)
		}
		gateHandler, err := gate.NewHandler(gate.Config{
			Threshold:       *gateLimit,
			Window:          *gateWindow,
			CookieName:      *cookieName,
			ChallengeSecret: challengeSecret,
			MarkerToken:     string(gateToken),
			BypassPrefixes:  commaSeparated(*gateBypass),
			Methods:         commaSeparated(*gateMethods),
		}, registry)
		if err != nil {
			logger.Fatal(err)
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
		errors <- (&server.Server{
			Socket:      *socket,
			SocketGroup: *socketGroup,
			Secret:      secret,
			MaxTTL:      *maxTTL,
			Backend:     backend,
			Metrics:     registry,
			Logger:      logger,
		}).ListenAndServe(ctx)
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

func metricsMux(registry *metrics.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", registry.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	return mux
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
