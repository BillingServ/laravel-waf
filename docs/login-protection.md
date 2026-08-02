# Login protection

Attach `laravel-waf.login` to the route or route group that accepts login
credentials:

```php
Route::post('/login', [LoginController::class, 'store'])
    ->middleware('laravel-waf.login');
```

The middleware checks both the source IP and the configured identifier (email
by default) before the controller runs. Failed, lockout, and successful Laravel
authentication events are also observed automatically when the package event
dispatcher is available:

- `Failed` increments the IP and IP-plus-identifier windows;
- `Lockout` creates a security finding and notification opportunity;
- `Login` clears the active windows when `clear_on_login` is enabled.

The identifier is hashed into cache keys. Credentials are not logged, stored,
sent to notifications, or added to metrics.

Useful settings in `config/laravel-waf.php` include:

```dotenv
LARAVEL_WAF_LOGIN_ENABLED=true
LARAVEL_WAF_LOGIN_FIELD=email
LARAVEL_WAF_LOGIN_MAX_ATTEMPTS=5
LARAVEL_WAF_LOGIN_DECAY_SECONDS=300
LARAVEL_WAF_LOGIN_BLOCK_AFTER=10
LARAVEL_WAF_LOGIN_AUTO_BLOCK=false
```

`LARAVEL_WAF_LOGIN_AUTO_BLOCK=true` can send an expiring IP decision to the
optional agent, but only when the agent is enabled. Laravel login protection
and host-level blocking are separate controls.
