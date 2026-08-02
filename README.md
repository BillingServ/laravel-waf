# Laravel WAF

Application-layer protection for Laravel applications running behind Nginx.
The package combines request inspection, rate limiting, browser challenges,
authentication protection, notifications, host block decisions, and metrics.

```text
upstream provider → iptables/ipset → Nginx → Laravel WAF → application
```

## Features

- Detects common XSS, SQL injection, remote file inclusion, and local file inclusion patterns.
- Detects command, template, NoSQL, LDAP, CRLF, and SSRF input patterns.
- Applies configurable request actions: reject, challenge, or log.
- Checks explicit route policies for methods, body size, content types, and required middleware.
- Enforces global and route-aware request limits using Laravel's cache store.
- Tracks repeated 404, 405, authentication, and other client error responses.
- Provides ALTCHA challenge verification, including support for existing bsv211 ALTCHA endpoints.
- Supports an opt-in `?test` diagnostic trigger for challenge pages.
- Applies country allow and deny rules through a local MaxMind database or a custom GeoIP resolver.
- Protects login endpoints by IP and identifier, observes Laravel authentication events, and can issue expiring agent block decisions.
- Sends security notifications through email or Slack with cooldown deduplication.
- Exposes bounded Prometheus metrics for decisions, findings, notifications, errors, and latency.
- Adds standard response security headers without replacing headers set by the application.
- Provides an opt-in outbound URL guard for integrations that accept remote URLs.
- Includes an optional Linux agent for signed, expiring IP block decisions sent over a Unix socket.

These controls operate at the Laravel application layer. They complement
parameterized database queries, output encoding, secure file handling, Nginx
limits, and upstream DDoS protection.

## Installation

```bash
composer require billingserv/laravel-waf
php artisan vendor:publish --tag=laravel-waf-config
```

Register the unified middleware globally:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(\BillingServ\LaravelWaf\Http\Middleware\WafProtection::class);
})
```

For applications using `app/Http/Kernel.php`, append the same class to the
global `$middleware` stack. `WafProtection` includes request inspection and
DDoS rate limiting; do not register `DdosProtection` alongside it.

The package uses Laravel's configured cache/rate-limiter store. Use Redis or
another shared store when running multiple PHP workers or application servers.

## Configuration

- [`docs/request-rules.md`](docs/request-rules.md): request rules, actions, exclusions, and GeoIP.
- [`docs/login-protection.md`](docs/login-protection.md): login middleware and authentication events.
- [`docs/notifications.md`](docs/notifications.md): email, Slack, and custom notification sinks.
- [`docs/challenge.md`](docs/challenge.md): ALTCHA configuration and challenge testing.
- [`docs/ddos-protection.md`](docs/ddos-protection.md): application rate limiting and layered deployment.
- [`docs/nginx-ddos.md`](docs/nginx-ddos.md): Nginx, iptables, and ipset guidance.
- [`docs/laravel-security.md`](docs/laravel-security.md): Laravel security controls and OWASP coverage.

## Nginx and host protection

Nginx should enforce connection limits, request rates, timeouts, body-size
limits, allowed methods, and cheap request rejection before Laravel runs. The
optional [`agent/`](agent/) service can update administrator-created ipsets
when the Laravel WAF sends a valid signed decision.

Laravel cannot protect a server after its network link or host resources have
already been saturated by a volumetric attack.

## Prometheus

Prometheus support is optional:

```bash
composer require promphp/prometheus_client_php
```

Enable the metrics route only behind Nginx allowlisting or authentication. Do
not expose it publicly by default. See [`docs/metrics.md`](docs/metrics.md).

Metric labels are bounded: IP addresses, URLs, query strings, headers, user
IDs, request bodies, and attack payloads are not used as labels.

## Security

Please review [`SECURITY.md`](SECURITY.md) before reporting a vulnerability.

## License

The MIT License. See [`LICENSE`](LICENSE).
