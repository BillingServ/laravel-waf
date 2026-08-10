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

Nginx must include the `http_auth_request_module`. Add an internal location that
proxies metadata to the Unix socket:

```nginx
location = /_laravel_waf_gate {
    internal;

    proxy_pass http://unix:/run/laravel-waf/gate.sock:/gate;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Laravel-Waf-Client-IP $remote_addr;
    proxy_set_header X-Laravel-Waf-Original-URI $request_uri;
    proxy_set_header X-Laravel-Waf-Original-Method $request_method;
    proxy_set_header Cookie $http_cookie;
}
```

Apply the check to the named dynamic application location, after Nginx has
already served real static files. Capture the marker returned by the private
subrequest and handle its `403` internally:

```nginx
location / {
    try_files $uri $uri/ @laravel_app;
}

location @laravel_app {
    auth_request /_laravel_waf_gate;
    auth_request_set $laravel_waf_gate_marker $upstream_http_x_laravel_waf_gate;
    auth_request_set $laravel_waf_gate_retry_after $upstream_http_retry_after;
    error_page 403 = @laravel_waf_challenge;
    error_page 401 =403 /__laravel_waf_blocked.html;

    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $realpath_root/index.php;
    fastcgi_param SCRIPT_NAME /index.php;

    # Never pass a public client-supplied marker to Laravel.
    fastcgi_param HTTP_X_LARAVEL_WAF_GATE "";
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

Keep repeated rate-blocked traffic out of PHP. Render Laravel WAF's
`BlockedResponse` once during deployment and install the resulting HTML at
`/etc/nginx/laravel-waf/__laravel_waf_blocked.html`. This preserves the
configured blocked design, theme, identity, logo, and favicon without booting
Laravel for every denied request:

```nginx
location = /__laravel_waf_blocked.html {
    internal;
    root /etc/nginx/laravel-waf;
    default_type text/html;
    charset utf-8;
    add_header Cache-Control "no-store" always;
    add_header Retry-After $laravel_waf_gate_retry_after always;
    add_header X-Laravel-Waf-Blocked "true" always;
}
```

The `=403` status override keeps the public response classified as blocked.
The internal static URI cannot be requested directly. Regenerate the file
whenever the Laravel WAF package or blocked-page branding changes.

The named location must invoke the same Laravel `public/index.php` entry point
as the site's normal PHP location while supplying the captured marker. Adapt
the PHP-FPM socket and document root to the host:

```nginx
location @laravel_waf_challenge {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $realpath_root/index.php;
    fastcgi_param SCRIPT_NAME /index.php;
    fastcgi_param HTTP_X_LARAVEL_WAF_GATE $laravel_waf_gate_marker;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

Keep `fastcgi_intercept_errors off` so an application-generated `403` is not
converted into a browser challenge. Validate the complete Nginx configuration
with `nginx -t` before reloading it.

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
/_waf/metrics
/_waf/blocked
/prometheus
```

They prevent challenge verification from challenging itself and do not consume
the pressure threshold. Override them with `--gate-bypass-prefixes` if the
Laravel paths were customized.

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
laravel_waf_decisions{action="challenge",scope="agent_gate",route="..."}
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
