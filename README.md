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
- Supports an opt-in Nginx/Go pre-application gate that detects traffic pressure
  and delegates browser challenges to Laravel.

These controls operate at the Laravel application layer. They complement
parameterized database queries, output encoding, secure file handling, Nginx
limits, and upstream DDoS protection.

## Installation

```bash
composer require billingserv/laravel-waf
php artisan vendor:publish --tag=laravel-waf-config
```

Register the unified middleware at the start of the `web` and `api` groups so
Laravel route names are available to route-aware limits and metrics:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware): void {
    $middleware->web(prepend: [
        \BillingServ\LaravelWaf\Http\Middleware\WafProtection::class,
    ]);
    $middleware->api(prepend: [
        \BillingServ\LaravelWaf\Http\Middleware\WafProtection::class,
    ]);
})
```

For applications using `app/Http/Kernel.php`, prepend the same class to the
`web` and `api` middleware groups. Global registration remains supported, but
requests may be labelled `unnamed` because global middleware can run before
Laravel resolves the route. `WafProtection` includes request inspection and
DDoS rate limiting; do not register `DdosProtection` alongside it.

The package uses Laravel's configured cache/rate-limiter store. Use Redis or
another shared store when running multiple PHP workers or application servers.

## Configuration

For the recommended ALTCHA deployment, the long list of tuning variables can
be replaced with:

```dotenv
LARAVEL_WAF_PRESET=balanced
LARAVEL_WAF_SECRET=replace-with-one-random-64-character-hex-secret
LARAVEL_WAF_AGENT_ENABLED=true
LARAVEL_WAF_AGENT_GATE_ENABLED=true
LARAVEL_WAF_ADAPTIVE_ENABLED=false
LARAVEL_WAF_METRICS_ENABLED=true
LARAVEL_WAF_METRICS_ALLOWED_IPS=replace-with-allowed-source-ip-or-cidr
```

`balanced` enables the automatic ALTCHA challenge flow, adaptive traffic
pressure, reject-mode request and behaviour rules, and automatic login,
rate-limit, and finding block decisions. The agent itself and the metrics
route remain explicit because they require local infrastructure and access
controls. `LARAVEL_WAF_SECRET` is the default for agent decisions, the Nginx
gate marker, browser-pass cookies, and ALTCHA verification. Existing granular
secret variables remain supported as overrides for older deployments. The
ALTCHA challenge-generating endpoint must use the same secret.

The default `standard` preset preserves the package's existing conservative
defaults. Any granular `LARAVEL_WAF_*` variable continues to override its
preset value, so remove the redundant entries when adopting the preset and
keep only deliberate exceptions. Published config remains available for
application-specific tuning.

- [`docs/request-rules.md`](docs/request-rules.md): request rules, actions, exclusions, and GeoIP.
- [`docs/login-protection.md`](docs/login-protection.md): login middleware and authentication events.
- [`docs/notifications.md`](docs/notifications.md): email, Slack, and custom notification sinks.
- [`docs/challenge.md`](docs/challenge.md): ALTCHA configuration and challenge testing.
- [`docs/ddos-protection.md`](docs/ddos-protection.md): application rate limiting and layered deployment.
- [`docs/nginx-ddos.md`](docs/nginx-ddos.md): Nginx, iptables, and ipset guidance.
- [`docs/agent-gate.md`](docs/agent-gate.md): coordinated Nginx, Go-agent, and Laravel browser challenges.
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

When metrics are enabled, Prometheus can scrape one configurable `/prometheus`
endpoint containing both Laravel and agent metrics. LWAFD can also expose its
own browser-viewable `:9919/metrics` endpoint behind an exact IP or CIDR
allowlist. See [`docs/metrics.md`](docs/metrics.md).

Metric labels are bounded: IP addresses, URLs, query strings, headers, user
IDs, request bodies, and attack payloads are not used as labels.

## Security

Please review [`SECURITY.md`](SECURITY.md) before reporting a vulnerability.

## Development

Run the complete PHP and Go verification suite from the repository root:

```bash
composer check
```

## License

The MIT License. See [`LICENSE`](LICENSE).
