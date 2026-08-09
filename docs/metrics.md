# Prometheus metrics

The recommended deployment exposes one protected Laravel endpoint containing
both the PHP WAF registry and the Go agent metrics:

```text
Prometheus over Tailscale → /prometheus → Laravel registry
                                     └→ agent 127.0.0.1:9919/metrics
```

The agent listener remains an internal loopback source. It does not need to be
reachable from Prometheus or exposed on the public network.

## Configuration

Install the optional PHP client and allow only the Prometheus server's exact
Tailscale address or a deliberately scoped CIDR:

```bash
composer require promphp/prometheus_client_php
```

```dotenv
LARAVEL_WAF_PRESET=balanced
LARAVEL_WAF_METRICS_ENABLED=true
LARAVEL_WAF_METRICS_ALLOWED_IPS=100.64.0.10
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

## Tailscale and Nginx

Use Tailscale ACLs and, where practical, bind the private virtual host or
listener to the server's Tailscale address. The application allowlist is a
second enforcement layer; Nginx can also deny the public location. Ensure
Laravel's trusted-proxy configuration makes `Request::ip()` the real Tailscale
client address before relying on the application allowlist.

Avoid allowlisting the whole `100.64.0.0/10` range unless every reachable
tailnet peer should be able to scrape metrics. An exact `/32` or `/128` for the
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
