# Prometheus metrics

The recommended deployment exposes one protected Laravel endpoint containing
both the PHP WAF registry and the Go agent metrics. LWAFD can additionally
expose its own metrics for browser access over Tailscale:

```text
Prometheus over Tailscale → /prometheus → Laravel registry
                                     └→ agent 127.0.0.1:9919/metrics

Browser over Tailscale ───────────────→ agent :9919/metrics
```

Use `/prometheus` when Prometheus needs all metrics in one response. The direct
`:9919/metrics` endpoint contains LWAFD metrics only.

## Configuration

Install the optional PHP client and allow only the Prometheus server's exact
Tailscale address or a deliberately scoped CIDR:

```bash
composer require promphp/prometheus_client_php
```

```dotenv
LARAVEL_WAF_PRESET=balanced
LARAVEL_WAF_METRICS_ENABLED=true
LARAVEL_WAF_METRICS_ALLOWED_IPS=replace-with-prometheus-source-ip-or-cidr
```

Multiple IPv4, IPv6, or CIDR entries are comma separated. A client outside the
allowlist receives a `404`, so the endpoint does not disclose its presence.
Metrics access defaults to loopback only, and an empty or invalid allowlist
fails closed.

The route and internal agent source are configurable when the deployment uses
different local values:

```dotenv
LARAVEL_WAF_METRICS_ROUTE=prometheus
LARAVEL_WAF_METRICS_INCLUDE_AGENT=true
LARAVEL_WAF_METRICS_AGENT_ENDPOINT=http://127.0.0.1:9919/metrics
```

For SSRF resistance, the agent source accepts only literal `127.0.0.1` or
`::1` HTTP endpoints. Keep the agent's `--metrics-address` on loopback. If the
agent cannot be collected, Laravel metrics remain available and the unified
response reports:

```text
laravel_waf_agent_metrics_up 0
```

On a successful merge the value is `1`.

The unified route and agent merge are the defaults whenever metrics are
enabled, regardless of preset. A deployment can temporarily restore the legacy
path with `LARAVEL_WAF_METRICS_ROUTE=_waf/metrics`, or disable the merge with
`LARAVEL_WAF_METRICS_INCLUDE_AGENT=false`.

Applications that previously published `config/laravel-waf.php` must merge the
new `metrics.allowed_ips` and `metrics.agent` keys from the package config
before these environment values can take effect. Preserve any existing custom
middleware or registry settings when updating the published file.

## Browser-viewable LWAFD metrics

LWAFD defaults to loopback. To make its own endpoint available over the
server's Tailscale IP, bind it to the host and apply the same exact IP or CIDR
policy deliberately selected for Laravel:

```text
--metrics-address METRICS_BIND_ADDRESS:9919
--metrics-allowed-ips PROMETHEUS_SOURCE_IP_OR_CIDR
```

Then an allowed peer can open:

```text
http://SERVER_TAILSCALE_IP:9919/metrics
```

Loopback is always allowed, preserving Laravel's local merge. Invalid
allowlist entries stop LWAFD at startup, and denied remote clients receive an
empty `404`. LWAFD uses the direct TCP peer address and does not trust
`X-Forwarded-For` or similar headers.

The Laravel and LWAFD allowlists are separate process settings. Keep
`LARAVEL_WAF_METRICS_ALLOWED_IPS` and `--metrics-allowed-ips` aligned. Binding
to `0.0.0.0` makes the port reachable on host interfaces, but the LWAFD
allowlist still rejects sources outside the configured ranges. Host firewall
rules and Tailscale ACLs remain useful additional layers.

## Tailscale and Nginx

Use Tailscale ACLs and, where practical, bind the private virtual host or
listener to the server's Tailscale address. The application allowlist is a
second enforcement layer; Nginx can also deny the public location. Ensure
Laravel's trusted-proxy configuration makes `Request::ip()` the real Tailscale
client address before relying on the application allowlist.

Avoid allowlisting the tailnet's complete address range unless every reachable
peer should be able to scrape metrics. An exact `/32` or `/128` for the
Prometheus server is preferable.

A minimal Prometheus job is:

```yaml
scrape_configs:
  - job_name: laravel-waf
    metrics_path: /prometheus
    scheme: https
    static_configs:
      - targets:
          - waf-server.tailnet-name.ts.net
```

Apply the site's TLS requirements in Prometheus and use the tailnet DNS name or
Tailscale IP that routes only over the tailnet.

To scrape LWAFD directly instead of collecting it through Laravel:

```yaml
scrape_configs:
  - job_name: lwafd
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
          - "SERVER_TAILSCALE_IP:9919"
```

Do not scrape the direct LWAFD target and Laravel's merged `/prometheus` target
into the same Prometheus job unless duplicate agent series are intentionally
handled.

## Exported metrics

The unified endpoint includes Laravel series such as:

```text
laravel_waf_decisions_total{action,scope,route}
laravel_waf_findings_total{category,rule,action,route}
laravel_waf_agent_blocks_total{outcome}
laravel_waf_notifications_total{channel,outcome}
laravel_waf_behavior_events_total{kind,outcome,route}
laravel_waf_errors_total{component}
laravel_waf_evaluation_duration_seconds
```

It also includes the agent's series:

```text
laravel_waf_agent_decisions_total{action,outcome}
laravel_waf_agent_firewall_operations_total{family,operation,outcome}
laravel_waf_agent_gate_requests_total{outcome}
```

Configure the PHP registry with persistent shared storage, normally Redis. An
in-memory registry is useful only for long-running workers or local development
because PHP-FPM workers do not share memory.

Do not add IP addresses, raw paths, query strings, headers, user IDs, request
bodies, or attack payloads as labels. Use structured redacted logs for
event-level investigation and combine these metrics with Nginx, PHP-FPM, host,
bandwidth, and firewall metrics in Grafana.
