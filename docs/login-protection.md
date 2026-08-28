# Login protection

Attach `laravel-waf.login` to the route or route group that accepts login
credentials:

```php
Route::post('/login', [LoginController::class, 'store'])
    ->middleware('laravel-waf.login');
```

Named Laravel middleware groups are supported as well. The WAF resolves the
group and honours `withoutMiddleware(...)` exclusions before deciding whether
a credential request may receive a browser challenge.

This control is separate from the generic DDoS limiter. When the complete
`laravel-waf` middleware is registered globally, a route using
`laravel-waf.login` is still counted in the global, route, and burst DDoS
buckets. It is not an exemption. If one of those buckets is exhausted, a
credential POST receives a normal `429` rather than a browser challenge. A
browser challenge cannot safely replay a submitted password, so this avoids
interrupting authentication while retaining the DDoS limit.

The middleware checks both the source IP and the configured identifier (email
by default) before the controller runs. Failed, lockout, and successful Laravel
authentication events are also observed automatically when the package event
dispatcher is available:

- `Failed` increments the IP and IP-plus-identifier windows;
- `Lockout` creates a security finding and notification opportunity;
- `Login` clears the active windows when `clear_on_login` is enabled.

The identifier is hashed into cache keys. Credentials are not logged, stored,
sent to notifications, or added to metrics.

The defaults already provide the limits shown below, so they do not need to be
copied into `.env`. `LARAVEL_WAF_PRESET=balanced` additionally enables the
automatic agent block. Granular overrides remain available when needed:

```dotenv
LARAVEL_WAF_LOGIN_ENABLED=true
LARAVEL_WAF_LOGIN_FIELD=email
LARAVEL_WAF_LOGIN_MAX_ATTEMPTS=5
LARAVEL_WAF_LOGIN_DECAY_SECONDS=300
LARAVEL_WAF_LOGIN_STATUS=429
LARAVEL_WAF_LOGIN_FAIL_MODE=open
LARAVEL_WAF_LOGIN_BLOCK_AFTER=10
LARAVEL_WAF_LOGIN_BLOCK_TTL=900
LARAVEL_WAF_LOGIN_AUTO_BLOCK=false
LARAVEL_WAF_LOGIN_CLEAR_ON_LOGIN=true
```

`LARAVEL_WAF_LOGIN_AUTO_BLOCK=true` can send an expiring IP decision to the
optional agent, but only when the agent is enabled. Laravel login protection
and host-level blocking are separate controls. Set `login.guards` in the
published configuration when only selected Laravel guards should be observed.

Login-limit responses include `Retry-After`, `Cache-Control: no-store`, and
`X-Laravel-Waf-Login: limited`. JSON clients receive a JSON message; browser
requests receive a plain-text response.
