# Go agent pre-application gate

The optional gate lets Nginx ask the Go agent whether a dynamic request should
continue before PHP is started. The Go process measures site-wide request
pressure and validates Laravel's signed browser-pass cookie. Laravel still owns
the challenge page, ALTCHA proof verification, redirect, and cookie issuance.

Aggregate pressure and individual abuse are intentionally separate. Crossing
the site-wide threshold challenges an unverified visitor but never creates a
firewall block. An unverified client that independently exceeds the gate's
per-client threshold is blocked because that decision is attributable to one
source rather than shared traffic pressure.

## Request flow

1. Nginx sends an `auth_request` subrequest over the private gate Unix socket.
2. Go counts the request in fixed site-wide and bounded per-client/path windows.
3. A valid IP-bound pass cookie, or an unverified request below both limits,
   receives `204`.
4. By default, request 61 from one unverified client in 60 seconds creates one
   `gate_rate_limit` block through LWAFD's existing firewall and audit path.
   LWAFD returns `401` so Nginx can serve a blocked response without booting PHP.
5. Under aggregate pressure, an unverified `GET` or `HEAD` receives `403` plus a private,
   authenticated gate marker.
6. Nginx internally retries the original request through PHP with that marker.
7. Laravel WAF validates the marker and returns “Checking your browser” before
   the requested route or controller executes.
8. After ALTCHA succeeds, Laravel sets the pass cookie. Go validates that cookie
   on subsequent requests and Nginx allows the application request.
9. Independent high-confidence Laravel findings can still send the existing
   signed `block_ip` decision to the agent. Accepted decisions are mirrored
   into the gate, so a proxied client is denied before PHP even when the
   backend INPUT rule sees the proxy as its network peer.

## Secrets and Laravel configuration

Generate one random secret and store it in a root-readable file for LWAFD and
in the application's secret environment:

```dotenv
LARAVEL_WAF_DDOS_MODE=challenge
LARAVEL_WAF_CHALLENGE_ENABLED=true
LARAVEL_WAF_SECRET=replace-with-one-random-64-character-hex-secret

LARAVEL_WAF_AGENT_GATE_ENABLED=true
LARAVEL_WAF_AGENT_GATE_RETRY_AFTER=60

LARAVEL_WAF_CHALLENGE_COOKIE_TTL=3600

# The Go gate replaces Laravel's site-wide adaptive counter. Keep route and
# passed-browser limits enabled, but do not run both pressure counters.
LARAVEL_WAF_ADAPTIVE_ENABLED=false
```

The file supplied with `--secret-file` must contain the exact
`LARAVEL_WAF_SECRET` value. LWAFD uses it for signed firewall decisions, gate
markers, and browser-pass validation. Laravel also uses it for ALTCHA
verification, so the challenge-generating endpoint must be configured with the
same value.

After changing the application environment, clear cached configuration:

```bash
php artisan optimize:clear
```

## Agent configuration

Build and test the agent, then add the gate flags to its service:

```bash
cd agent
go test ./...
./build.sh

sudo ./bin/lwafd \
  --socket /run/laravel-waf/agent.sock \
  --socket-group www-data \
  --secret-file /etc/laravel-waf/agent.secret \
  --metrics-ingest-socket /run/laravel-waf/metrics.sock \
  --metrics-ingest-socket-group www-data \
  --gate-socket /run/laravel-waf/gate.sock \
  --gate-socket-group www-data \
  --gate-threshold 600 \
  --gate-window 60s \
  --challenge-cookie laravel_waf_challenge
```

The defaults mirror Laravel's normal limits: 60 unverified requests to one path
or 120 total requests from one client in the same gate window, followed by a
900-second block. Advanced deployments can change the path threshold with
`--gate-client-threshold` (the total remains twice that value) and the TTL with
`--gate-block-ttl`; setting the threshold to `0` disables only gate-generated
blocks.

Gate mode is disabled when `--gate-socket` is omitted. Existing agent installs
therefore retain block/unblock-only behavior until explicitly changed.
When the default ledger is available, active records from
`/var/lib/laravel-waf/blocks.json` are loaded when the gate starts, so this
application-edge denial survives an LWAFD restart.

## Nginx configuration

Nginx must include the `http_auth_request_module`. The Ansible role installs a
reusable server-context include at:

```text
/etc/nginx/conf.d/lwafd/server.conf
```

Include it once inside the HTTPS `server` block, after trusted real-IP handling
has established the real `$remote_addr`:

```nginx
include /etc/nginx/conf.d/lwafd/server.conf;
```

The include owns the exact `/prometheus` proxy, the private `auth_request`
subrequest, Laravel's named dynamic and challenge locations, direct-PHP bypass
protection, and the static blocked response. The role renders Laravel WAF's
full blocked design once to
`/etc/nginx/laravel-waf/__laravel_waf_blocked.html`, so blocked traffic does not
boot PHP. The file sits in a subdirectory of `conf.d` so a conventional
top-level `conf.d/*.conf` wildcard cannot accidentally load server-only
locations in the global `http` context.

The role validates the complete configuration with `nginx -t`, reloads only
after successful validation, and restores both the site and include files if a
live probe fails.

`$remote_addr` must already represent the real client. If a CDN or load balancer
is present, configure Nginx real-IP handling only for explicitly trusted proxy
ranges before enabling the gate.

An INPUT firewall rule sees the network peer, not `X-Forwarded-For`. If a
different machine proxies public traffic to the protected host, the backend
gate can still deny the forwarded client before PHP, but a backend IPSet entry
for that client cannot match packets whose source is the proxy. Put equivalent
network enforcement on the proxy or upstream edge when packets must be dropped
before they reach the backend.

## Bypasses and methods

The default gate bypass prefixes are:

```text
/_waf/challenge
/_waf/blocked
```

They prevent challenge verification from challenging itself and do not consume
the pressure threshold. Override them with `--gate-bypass-prefixes` if the
Laravel paths were customized.

The exact `/prometheus` Nginx location never invokes the gate. When iptables
management is enabled, LWAFD also excludes `--metrics-allowed-ips` from its
block-set DROP rule. Nginx and LWAFD still enforce the metrics source
allowlist.

Only original `GET` and `HEAD` requests are challenged by default. Configure
`--gate-methods` only after defining how non-idempotent requests should be
handled; the package deliberately does not replay POST bodies after a challenge.

## Metrics

The agent's existing loopback metrics listener now exports:

```text
laravel_waf_agent_gate_requests_total{outcome="allowed"}
laravel_waf_agent_gate_requests_total{outcome="challenged"}
laravel_waf_agent_gate_requests_total{outcome="bypassed"}
laravel_waf_agent_gate_requests_total{outcome="allowed_method"}
laravel_waf_agent_gate_requests_total{outcome="invalid"}
laravel_waf_agent_gate_requests_total{outcome="rate_blocked"}
laravel_waf_agent_gate_requests_total{outcome="blocked"}
laravel_waf_agent_gate_requests_total{outcome="rate_block_error"}
```

Laravel records accepted gate markers as:

```text
laravel_waf_decisions_total{action="challenge",scope="agent_gate",route="..."}
```

## Rollout

1. Deploy the updated agent with a high gate threshold and verify its health and
   metrics sockets.
2. Add the Nginx internal gate location and named challenge location.
3. Enable the Laravel gate configuration and disable Laravel adaptive pressure.
4. Test with a temporary low Go threshold from a private browser window.
5. Restore the production threshold and monitor challenged/pass ratios.
6. Confirm request 61 from one unverified test client records exactly one
   `gate_rate_limit` block, while requests from many independent clients only
   trigger the aggregate challenge.
7. Confirm whether the host receives client connections directly or through a
   separate proxy, and place network-layer enforcement at the actual ingress.
