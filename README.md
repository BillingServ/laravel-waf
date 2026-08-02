# Laravel WAF

Laravel application-layer protection for Nginx-hosted applications, starting with DDoS-conscious request limiting, challenge integration, host block decisions, and Prometheus observability.

This project is deliberately layered:

```text
upstream provider → iptables/ipset → Nginx → Laravel WAF → application
```

It is not a replacement for upstream DDoS mitigation. Laravel cannot protect a server after its network link or host has already been saturated.

## Current scope

The first implementation focuses on:

- application request-rate limiting;
- route-aware limits without inspecting request bodies;
- an extension point for challenge providers;
- optional, expiring IP block decisions for `laravel-waf-agent`;
- Prometheus-compatible decision and latency metrics;
- Nginx and iptables/ipset deployment guidance.

XSS, SQL injection, RFI, LFI, geo rules, login protection, notifications, and XDP/eBPF are intentionally out of scope for this first slice.

## Installation

```bash
composer require billingserv/laravel-waf
php artisan vendor:publish --tag=laravel-waf-config
```

Add the middleware to the application's global middleware stack. The exact registration depends on the Laravel version:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(\\BillingServ\\LaravelWaf\\Http\\Middleware\\DdosProtection::class);
})
```

For Laravel versions using `app/Http/Kernel.php`, append the same class to `$middleware`.

The middleware uses Laravel's configured cache/rate-limiter store. Use Redis or another shared store when the application has multiple PHP workers or servers.

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
