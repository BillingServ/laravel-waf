# Request rules

`WafProtection` runs the request rules before the shared-cache DDoS limiter.
The standalone `RequestInspection` middleware is available when rate limiting
is managed elsewhere.

The built-in categories are:

- `xss`: script elements, event handlers, executable schemes, and dangerous HTML elements;
- `sqli`: common tautologies, union and stacked queries, time-delay functions, database probes, and SQL comments;
- `rfi`: dangerous stream wrappers and remote URLs in file-like parameters;
- `lfi`: traversal, null bytes, sensitive local files, and file wrappers;
- `geo`: country allow/deny policy through a resolver.

Input is collected from the path, query string, parsed body, and route
parameters by default. Headers and cookies are opt-in. Values, total bytes,
nesting depth, and value count are capped before matching. The matcher applies
limited URL decoding and HTML entity decoding; it never logs or emits the raw
value.

## Actions

Set a global action with `LARAVEL_WAF_RULES_MODE`:

```dotenv
LARAVEL_WAF_RULES_MODE=reject
```

Valid actions are `reject`, `challenge`, and `log`. A category can override the
global action, for example:

```dotenv
LARAVEL_WAF_XSS_ACTION=challenge
LARAVEL_WAF_SQLI_ACTION=reject
```

`challenge` requires `LARAVEL_WAF_CHALLENGE_ENABLED=true`; otherwise the
finding is rejected. Use `log` while tuning exclusions or custom application
inputs. The default response is a generic 403 and deliberately does not reveal
which rule matched.

Exclusions are configured in the published file:

```php
'rules' => [
    'categories' => [
        'xss' => ['exclude_fields' => ['content', 'profile.*']],
    ],
],
```

Exclusions reduce protection and should be as narrow as possible. These
signatures are a detection layer, not a replacement for parameterized queries,
output encoding, or safe filesystem APIs.

## GeoIP

Geo rules are disabled until a policy is configured. The optional built-in
resolver uses a local MaxMind GeoIP2/GeoLite2 database:

```bash
composer require geoip2/geoip2
```

```dotenv
LARAVEL_WAF_GEO_ENABLED=true
LARAVEL_WAF_GEOIP_DATABASE=/var/lib/GeoIP/GeoLite2-Country.mmdb
LARAVEL_WAF_GEOIP_DENIED_COUNTRIES=CN,RU
# Or use an allowlist:
# LARAVEL_WAF_GEOIP_ALLOWED_COUNTRIES=GB,IE,NL
LARAVEL_WAF_GEOIP_UNKNOWN=allow
```

Applications can bind `BillingServ\LaravelWaf\Contracts\GeoIpResolver` to
their own database or service. Country codes are normalized to two-letter
uppercase codes. The resolver is local to the request and is not queried over
the network by this package.
