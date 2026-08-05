# DDoS protection scope

The Laravel WAF uses layered controls:

```text
upstream provider → iptables/ipset → Nginx → Laravel WAF → application
```

## What each layer does

- Upstream provider: protects the network link and upstream routing from volumetric attacks.
- iptables/ipset: drops already-known abusive sources before Nginx. The optional agent only updates expiring sets; administrators own the firewall rules.
- Nginx: handles connection limits, request rates, timeouts, body/header limits, and cheap method/host rejection.
- Laravel WAF: applies shared-cache request limits, emits challenge decisions,
  verifies ALTCHA responses when enabled, sends optional high-confidence
  blocks to the agent, records bounded metrics, and can run the request rules
  described in [`request-rules.md`](request-rules.md).

Use the `laravel-waf` middleware alias (or `WafProtection::class`) for the
complete package flow. It runs request inspection before DDoS rate limiting.
Registering `WafProtection` and `DdosProtection` together applies the rate
limiter twice.

Laravel is not able to observe requests that Nginx or iptables reject. Monitor Nginx and host metrics alongside the Laravel WAF metrics.

## Fail-open behavior

The Laravel middleware defaults to `fail_mode=open` so a cache or metrics failure does not turn into an application-wide outage. Nginx remains the earlier protection layer. Set `LARAVEL_WAF_DDOS_FAIL_MODE=closed` only when the protected route can tolerate a temporary 503 during rate-limiter failure.

## Agent activation

The agent and automatic host blocks are disabled by default. Enable them only after confirming:

1. Laravel sees the real client IP through the configured proxy chain.
2. The ipset rules cannot block trusted administration or internal traffic.
3. The agent socket is local and has restrictive ownership/mode.
4. TTLs, metrics, and an unblock procedure have been tested.

Do not send every rate-limited request to the agent. The Laravel middleware has a cooldown so a single source produces at most one block decision per cooldown window.

Challenge mode has its own per-IP verification limit and a bounded post-
verification limit. A successful challenge is therefore a temporary change in
traffic policy, not an unlimited allowlist.

## Adaptive traffic pressure

Adaptive mode adds a site-wide request counter on top of the normal per-client
limits. Normal traffic passes without a challenge. Once the shared counter
crosses the configured threshold, browsers without a valid pass cookie receive
the configured challenge while verified browsers continue under the bounded
post-verification limits.

```dotenv
LARAVEL_WAF_ADAPTIVE_ENABLED=true
LARAVEL_WAF_ADAPTIVE_CHALLENGE_AFTER=600
LARAVEL_WAF_ADAPTIVE_WINDOW_SECONDS=60
```

This measures Laravel request pressure, not CPU or memory utilization. Use a
shared Redis cache in multi-worker or multi-server deployments so every worker
observes the same pressure window. Nginx and upstream limits remain responsible
for traffic that should not reach PHP.

For pressure detection before PHP, use the optional
[`Go agent pre-application gate`](agent-gate.md). When that gate is enabled,
disable this Laravel adaptive counter to avoid measuring and challenging the
same traffic twice. Route limits and verified-browser limits remain active.
