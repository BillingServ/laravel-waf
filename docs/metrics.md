# Prometheus metrics

LWAFD owns one registry containing both Laravel WAF and agent metrics. Laravel
sends bounded, signed events over a private Unix socket and never renders or
stores Prometheus data itself:

```text
Laravel middleware ──signed events──→ /run/laravel-waf/metrics.sock
                                            │
                                            ▼
Prometheus over HTTPS → /prometheus → LWAFD 127.0.0.1:9919/metrics

Browser over Tailscale ─────────────→ LWAFD :9919/metrics
```

Both URLs expose the same unified registry. Scrape one of them, not both.

LWAFD puts its hostname in the `instance` label on every series and publishes
an always-present discovery metric:

```text
laravel_waf_info{instance="app.example.com",application="lwafd",version="REVISION"} 1
```

The operating-system hostname is used automatically. The advanced
`--metrics-instance` agent option can override it when required.

## Configuration

No PHP Prometheus package or Redis metrics store is required. Enable the agent
and metrics, then allow only the intended Prometheus source IP or CIDR:

```dotenv
LARAVEL_WAF_SECRET=replace-with-one-strong-shared-secret
LARAVEL_WAF_PRESET=balanced
LARAVEL_WAF_AGENT_ENABLED=true
LARAVEL_WAF_METRICS_ENABLED=true
LARAVEL_WAF_METRICS_ALLOWED_IPS=replace-with-prometheus-source-ip-or-cidr
```

Ansible reads the allowlist from Laravel's environment and supplies it to both
Nginx and LWAFD. Multiple IPv4, IPv6, or CIDR values are comma separated. An
empty allowlist leaves the direct listener on loopback; invalid values stop the
deployment or LWAFD startup rather than exposing metrics.

Laravel sends events to `/run/laravel-waf/metrics.sock` by default. The role
creates this socket with the PHP-FPM group and passes the same secret file used
for block decisions and challenge cookies. Only deployments with a custom
runtime path need the matching advanced settings:

```dotenv
LARAVEL_WAF_METRICS_SOCKET=/run/custom/lwafd-metrics.sock
```

```text
--metrics-ingest-socket /run/custom/lwafd-metrics.sock
```

Metric delivery is fire-and-forget. A missing or busy metrics socket cannot
delay or fail a protected request, and it is separate from the firewall
decision socket. LWAFD validates the HMAC, metric schema, label names and
values, observation range, payload size, and a global series limit before
updating the registry.

## Nginx endpoint

The Ansible role installs the reusable server-context configuration at:

```text
/etc/nginx/conf.d/lwafd/server.conf
```

The HTTPS virtual host contains only:

```nginx
include /etc/nginx/conf.d/lwafd/server.conf;
```

Its exact `/prometheus` location applies the source allowlist and proxies to
LWAFD over loopback. Laravel and PHP-FPM are not started for a scrape. Clients
outside the Nginx allowlist receive `403`; direct LWAFD clients outside its
allowlist receive an empty `404`.

## Browser-viewable endpoint

When an allowlist is configured, Ansible binds the LWAFD listener to
`0.0.0.0:9919`. An allowed Tailscale peer can open:

```text
http://SERVER_TAILSCALE_IP:9919/metrics
```

LWAFD checks the direct TCP peer and deliberately ignores proxy headers.
Loopback is always allowed so Nginx can proxy the HTTPS endpoint.

When LWAFD manages iptables, `--metrics-allowed-ips` also populates dedicated
IPv4 and IPv6 allow-sets. The WAF DROP rule applies only when a source is in the
block set and absent from the metrics allow-set. An approved scraper can
therefore reach `/prometheus` while its address has an active WAF block.

The kernel cannot inspect an HTTPS path, so an approved metrics source is
exempt from LWAFD's port 80/443 DROP rule as a whole. Nginx still exposes only
`/prometheus` to that source, and the pre-application gate continues rejecting
blocked requests to non-bypass dynamic routes. Prefer an exact `/32` or `/128`
unless every peer in a larger range should have this access.

## Prometheus jobs

Through Nginx and the site's TLS endpoint:

```yaml
scrape_configs:
  - job_name: lwafd
    metrics_path: /prometheus
    scheme: https
    honor_labels: true
    static_configs:
      - targets:
          - waf-server.tailnet-name.ts.net
```

Or directly from LWAFD over Tailscale:

```yaml
scrape_configs:
  - job_name: lwafd
    metrics_path: /metrics
    scheme: http
    honor_labels: true
    static_configs:
      - targets:
          - "SERVER_TAILSCALE_IP:9919"
```

## Exported metrics

Laravel events produce:

```text
laravel_waf_decisions_total{action,scope,route}
laravel_waf_findings_total{category,rule,action,route}
laravel_waf_agent_blocks_total{outcome}
laravel_waf_notifications_total{channel,outcome}
laravel_waf_behavior_events_total{kind,outcome,route}
laravel_waf_errors_total{component}
laravel_waf_evaluation_duration_seconds
```

LWAFD also exports:

```text
laravel_waf_agent_decisions_total{action,outcome}
laravel_waf_agent_firewall_operations_total{family,operation,outcome}
laravel_waf_agent_gate_requests_total{outcome}
laravel_waf_agent_metric_events_total{outcome}
```

Counters reset when LWAFD restarts, which Prometheus handles as a normal process
restart. Do not add IP addresses, raw paths, query strings, headers, user IDs,
request bodies, or attack payloads as labels. Use redacted logs for event-level
investigation and combine these metrics with Nginx, PHP-FPM, host, bandwidth,
and firewall metrics in Grafana.

## Empty Laravel metric families

Prometheus exposition includes `HELP` and `TYPE` lines before a metric has any
observations. LWAFD always emits each known metric-ingest outcome, including:

```text
laravel_waf_agent_metric_events_total{instance="app.example.com",outcome="accepted"} 0
```

If `accepted` remains zero after a request reaches Laravel, no application
metric event has entered the registry. Confirm the deployed Laravel package
contains the Unix-socket metrics sink, both agent and metrics settings are
enabled, cached Laravel configuration has been cleared, and the PHP-FPM user
can traverse `/run/laravel-waf` and write to `metrics.sock`. A non-zero
`rejected` or `rejected_schema` outcome instead means LWAFD received an event
but rejected its signature or schema.
