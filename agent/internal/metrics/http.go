package metrics

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

var loopbackPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// NewHTTPHandler exposes agent health and Prometheus metrics only to loopback
// and explicitly configured IP addresses or CIDR ranges. It intentionally
// ignores proxy headers because the listener is designed for direct access.
func NewHTTPHandler(registry *Registry, allowed []string) (http.Handler, error) {
	if registry == nil {
		return nil, fmt.Errorf("metrics registry is required")
	}

	prefixes := append([]netip.Prefix(nil), loopbackPrefixes...)
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		prefix, err := metricsPrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", registry.Handler())
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
	})

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !metricsClientAllowed(request.RemoteAddr, prefixes) {
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusNotFound)

			return
		}

		mux.ServeHTTP(response, request)
	}), nil
}

func metricsPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("invalid metrics allowed IP or CIDR %q", value)
		}

		return prefix.Masked(), nil
	}

	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid metrics allowed IP or CIDR %q", value)
	}
	address = address.Unmap()

	return netip.PrefixFrom(address, address.BitLen()), nil
}

func metricsClientAllowed(remoteAddress string, prefixes []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}

	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return false
	}
	address = address.Unmap()

	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}

	return false
}
