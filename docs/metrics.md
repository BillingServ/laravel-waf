# Prometheus metrics

Prometheus support is optional. Install the client library in the Laravel application:

```bash
composer require promphp/prometheus_client_php
```

Configure the client registry with persistent shared storage, normally Redis, before enabling the Laravel WAF metrics route. An in-memory registry is only useful for long-running workers or local development because PHP-FPM workers do not share memory.

Enable the route with:

```dotenv
LARAVEL_WAF_METRICS_ENABLED=true
```

Protect the resulting `/_waf/metrics` endpoint with Nginx IP allowlisting or authentication. The route is exempt from Laravel request limiting so a scrape cannot consume a client rate-limit window.

The Laravel package records bounded series such as:

```text
laravel_waf_decisions_total{action,scope,route}
laravel_waf_findings_total{category,rule,action,route}
laravel_waf_agent_blocks_total{outcome}
laravel_waf_notifications_total{channel,outcome}
laravel_waf_errors_total{component}
laravel_waf_evaluation_duration_seconds
```

The agent exposes:

```text
laravel_waf_agent_decisions_total{action,outcome}
laravel_waf_agent_firewall_operations_total{family,operation,outcome}
```

Do not add IP addresses, raw paths, query strings, headers, user IDs, request bodies, or attack payloads as labels. Use structured redacted logs for event-level investigation and combine these metrics with Nginx, PHP-FPM, host, bandwidth, and firewall metrics in Grafana.
