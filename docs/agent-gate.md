# Go agent pre-application gate

The optional gate lets Nginx ask the Go agent whether a dynamic request should
continue before PHP is started. The Go process measures site-wide request
pressure and validates Laravel's signed browser-pass cookie. Laravel still owns
the challenge page, ALTCHA proof verification, redirect, and cookie issuance.

The firewall and challenge outcomes are intentionally separate. A challenged
IP must not be added to IPSet because a firewall-dropped client cannot receive
an HTTP challenge page.

## Request flow

1. Nginx sends an `auth_request` subrequest over the private gate Unix socket.
2. Go counts the request in a fixed site-wide window.
3. Below the threshold, or with a valid IP-bound pass cookie, Go returns `204`.
4. Under pressure, an unverified `GET` or `HEAD` receives `403` plus a private,
   authenticated gate marker.
5. Nginx internally retries the original request through PHP with that marker.
6. Laravel WAF validates the marker and returns “Checking your browser” before
   the requested route or controller executes.
7. After ALTCHA succeeds, Laravel sets the pass cookie. Go validates that cookie
   on subsequent requests and Nginx allows the application request.
8. Independent high-confidence Laravel findings can still send the existing
   signed `block_ip` decision to the agent.

## Secrets and Laravel configuration

Generate separate random values for the browser cookie and gate marker. Store
the same values in root-readable files for the agent and in the application's
secret environment:

```dotenv
LARAVEL_WAF_DDOS_MODE=challenge
LARAVEL_WAF_CHALLENGE_ENABLED=true

LARAVEL_WAF_AGENT_GATE_ENABLED=true
LARAVEL_WAF_AGENT_GATE_TOKEN=replace-with-at-least-32-random-bytes
LARAVEL_WAF_AGENT_GATE_RETRY_AFTER=60

LARAVEL_WAF_CHALLENGE_COOKIE_SECRET=replace-with-a-different-32-byte-secret
LARAVEL_WAF_CHALLENGE_COOKIE_TTL=3600

# The Go gate replaces Laravel's site-wide adaptive counter. Keep route and
# passed-browser limits enabled, but do not run both pressure counters.
LARAVEL_WAF_ADAPTIVE_ENABLED=false
```

The file supplied with `--challenge-secret-file` must contain the exact
`LARAVEL_WAF_CHALLENGE_COOKIE_SECRET` value. The file supplied with
`--gate-token-file` must contain the exact `LARAVEL_WAF_AGENT_GATE_TOKEN` value.
Do not reuse the ALTCHA HMAC key for either purpose.

After changing the application environment, clear cached configuration:

```bash
php artisan optimize:clear
```

## Agent configuration

Build and test the agent, then add the gate flags to its service:

```bash
cd agent
go test ./...
go build -o bin/laravel-waf-agent ./cmd/laravel-waf-agent

sudo ./bin/laravel-waf-agent \
  --socket /run/laravel-waf/agent.sock \
  --socket-group www-data \
  --secret-file /etc/laravel-waf/agent.secret \
  --gate-socket /run/laravel-waf/gate.sock \
  --gate-socket-group www-data \
  --gate-threshold 600 \
  --gate-window 60s \
  --challenge-cookie laravel_waf_challenge \
  --challenge-secret-file /etc/laravel-waf/challenge.secret \
  --gate-token-file /etc/laravel-waf/gate-token.secret
```

Gate mode is disabled when `--gate-socket` is omitted. Existing agent installs
therefore retain block/unblock-only behavior until explicitly changed.

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
    error_page 403 = @laravel_waf_challenge;

    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $realpath_root/index.php;
    fastcgi_param SCRIPT_NAME /index.php;

    # Never pass a public client-supplied marker to Laravel.
    fastcgi_param HTTP_X_LARAVEL_WAF_GATE "";
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

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

## Bypasses and methods

The default gate bypass prefixes are:

```text
/_waf/challenge
/_waf/metrics
/_waf/blocked
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
6. Leave automatic IP blocking disabled until real-IP handling and decision
   quality have been independently verified.
