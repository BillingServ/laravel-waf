# Laravel WAF

Laravel application-layer WAF protection for Nginx-hosted applications. It combines request inspection, rate limiting, challenge integration, optional host block decisions, authentication protection, notifications, and Prometheus observability.

This project is deliberately layered:

```text
upstream provider → iptables/ipset → Nginx → Laravel WAF → application
```

It is not a replacement for upstream DDoS mitigation. Laravel cannot protect a server after its network link or host has already been saturated.

## Current scope

The first implementation supports:

- XSS, SQL injection, RFI, and LFI request signatures with bounded input inspection;
- configurable allow/deny GeoIP policies through a built-in MaxMind resolver or a custom resolver;
- route-aware application request-rate limiting;
- login protection middleware plus Laravel failed-login, lockout, and successful-login events;
- optional email and Slack security notifications with cooldown deduplication;
- challenge mode with a complete ALTCHA verification flow;
- optional, expiring IP block decisions for `laravel-waf-agent`;
- Prometheus-compatible decision and latency metrics;
- Nginx and iptables/ipset deployment guidance.

These are application-layer controls. They complement, rather than replace,
parameterized database queries, output encoding, secure file handling, Laravel
authentication throttling, Nginx limits, and upstream DDoS mitigation.

## Installation

```bash
composer require billingserv/laravel-waf
php artisan vendor:publish --tag=laravel-waf-config
```

ALTCHA support is included. The package accepts both the legacy ALTCHA
payload format used by existing bsv211 deployments and the current ALTCHA
PHP library format. See [`docs/challenge.md`](docs/challenge.md).

Add the unified middleware to the application's global middleware stack. It
runs request rules before the existing DDoS limiter:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(\BillingServ\LaravelWaf\Http\Middleware\WafProtection::class);
})
```

For Laravel versions using `app/Http/Kernel.php`, append the same class to
`$middleware`. Use `DdosProtection` or `RequestInspection` separately only
when you deliberately want one layer without the other; do not register
`WafProtection` and `DdosProtection` together.

The middleware uses Laravel's configured cache/rate-limiter store. Use Redis or
another shared store when the application has multiple PHP workers or servers.

See [`docs/request-rules.md`](docs/request-rules.md),
[`docs/login-protection.md`](docs/login-protection.md), and
[`docs/notifications.md`](docs/notifications.md) for configuration.

## Nginx comes first

Laravel is too late to be the only DDoS control. Apply request, connection, timeout, body-size, and method restrictions in Nginx first. See [`docs/nginx-ddos.md`](docs/nginx-ddos.md).

## Agent

The optional [`agent/`](agent/) component is a small Linux service that accepts signed, expiring block decisions over a local Unix socket and updates administrator-created ipsets. It does not run XDP/eBPF and does not modify iptables rules automatically.

## Metrics

Prometheus support is optional:

```bash
composer require promphp/prometheus_client_php
```

Configure its shared storage, and enable the metrics route only behind Nginx allowlisting or authentication. Never expose the endpoint publicly by default.

See [`docs/metrics.md`](docs/metrics.md) for the metric names and Grafana integration notes.

Metric labels are deliberately bounded. IP addresses, URLs, query strings, headers, user IDs, and request bodies are never metric labels.

## Security

Please review [`SECURITY.md`](SECURITY.md) before reporting a vulnerability.

## License

The MIT License. See [`LICENSE`](LICENSE).
