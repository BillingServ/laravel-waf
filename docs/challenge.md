# Challenge mode

Challenge mode is an application-layer control for clients that exceed the
configured request limits. It is not a replacement for Nginx, iptables, or
upstream DDoS protection.

## ALTCHA with the existing bsv211 endpoint

The package reads the existing bsv211 variables by default:

```dotenv
LARAVEL_WAF_DDOS_MODE=challenge
LARAVEL_WAF_CHALLENGE_ENABLED=true
LARAVEL_WAF_CHALLENGE_PROVIDER=altcha
LARAVEL_WAF_CHALLENGE_PATH=_waf/challenge/verify

ALTCHA_CHALLENGE_URL=https://example.test/altcha/challenge
ALTCHA_HMAC_KEY=replace-with-the-same-secret-used-by-the-challenge-endpoint
```

Install the package as normal. The official ALTCHA PHP library is installed
as a package dependency and is used to verify the submitted payload. The
legacy custom endpoint should return a fresh, short-lived challenge and must
not be cached.

WAF-specific variables can override the application variables when the
application has more than one ALTCHA integration:

```dotenv
LARAVEL_WAF_ALTCHA_CHALLENGE_URL=https://example.test/altcha/challenge
LARAVEL_WAF_ALTCHA_HMAC_KEY=another-secret
LARAVEL_WAF_ALTCHA_VERIFICATION=solution
LARAVEL_WAF_ALTCHA_FIELD=altcha
LARAVEL_WAF_ALTCHA_MAX_PAYLOAD_BYTES=65536
LARAVEL_WAF_ALTCHA_CHALLENGE_ATTRIBUTE=challengeurl
LARAVEL_WAF_ALTCHA_SCRIPT_URL=https://cdn.example.test/altcha.min.js

LARAVEL_WAF_CHALLENGE_BRAND_NAME=Example
LARAVEL_WAF_CHALLENGE_LOGO_URL=/assets/logo.svg
LARAVEL_WAF_CHALLENGE_FAVICON_URL=/favicon.ico
LARAVEL_WAF_CHALLENGE_THEME=auto
LARAVEL_WAF_CHALLENGE_COOKIE_SECURE=auto
```

`LARAVEL_WAF_ALTCHA_CHALLENGE_ATTRIBUTE` may be `challengeurl` for the
existing widget integration or `challenge` for newer widget integrations.
The challenge field and script URL are configurable so the WAF does not need
to own the application's frontend setup.

The interstitial is white-labeled by default and does not display the package
name. Set the optional challenge brand, logo, and favicon variables when the
site should identify itself on the page. Logo and favicon URLs may be
same-origin paths or HTTPS URLs.

`LARAVEL_WAF_CHALLENGE_COOKIE_SECURE=auto` marks the pass cookie as secure when
the current request is HTTPS and leaves it usable for local HTTP development.
Use `true` when HTTPS is mandatory in every environment.

The WAF pass cookie is a signed token rather than a Laravel application cookie.
The package excludes it from `EncryptCookies` so globally registered WAF
middleware can read it before the web middleware stack runs.

## Server signatures

For an ALTCHA Sentinel/server-signature integration, use:

```dotenv
LARAVEL_WAF_ALTCHA_VERIFICATION=server_signature
LARAVEL_WAF_ALTCHA_HMAC_KEY=the-server-signature-secret
LARAVEL_WAF_ALTCHA_CHALLENGE_ATTRIBUTE=challenge
```

The verifier supports the legacy ALTCHA PHP namespace and the current
namespace, including PBKDF2, Argon2id, and Scrypt solution payloads where the
installed ALTCHA library and PHP extensions support them.

## What happens after verification

1. The WAF renders an ALTCHA page containing a signed, IP-bound request token.
2. The browser posts the token and ALTCHA payload to the package's internal
   verification route.
3. The WAF verifies the payload, rejects replayed tokens/payloads, and issues
   a short-lived signed challenge cookie.
4. The browser is redirected to the original GET/HEAD URL.
5. The challenge cookie receives a separate bounded rate limit; it is not an
   unlimited bypass.

The internal verification route is exempt from the ordinary request limiter,
but it has its own per-IP verification limit. Keep it protected by the Nginx
limits described in [`nginx-ddos.md`](nginx-ddos.md).

## Custom integrations

Applications can replace either integration point in a service provider:

```php
$this->app->bind(
    \BillingServ\LaravelWaf\Contracts\ChallengeVerifier::class,
    App\Security\MyChallengeVerifier::class,
);

$this->app->bind(
    \BillingServ\LaravelWaf\Contracts\ChallengeResponder::class,
    App\Security\MyChallengeResponder::class,
);
```

Custom responders should preserve the no-store response headers and should
return a same-origin verification flow. Custom verifiers must fail closed for
malformed or expired payloads.

## Manual test trigger

To render the blocked page without waiting for a rate limit, enable the
diagnostic trigger temporarily:

```dotenv
LARAVEL_WAF_TESTING_ENABLED=true
```

Then open any route that uses the WAF middleware with `?test`, for example:

```text
https://example.test/login?test
```

The trigger is disabled by default and is ignored in production. It can be
enabled deliberately in production with `LARAVEL_WAF_TESTING_ALLOW_PRODUCTION`
but should normally only be used in local or staging environments. The
parameter name and an optional required value are configurable with
`LARAVEL_WAF_TESTING_PARAMETER` and `LARAVEL_WAF_TESTING_VALUE`.

The trigger returns a `403` blocked response and never issues a challenge
token or verification cookie. It is intended for checking the blocked state
of the page; normal challenge behavior is still exercised by exceeding the
configured limit. Set `LARAVEL_WAF_CHALLENGE_THEME=dark` to force the dark
theme, or leave it as `auto` to follow the visitor's system preference.

## Livewire and Filament

Livewire form submissions are handled as JSON requests. When request
inspection blocks a Livewire update, the package returns Livewire's redirect
response shape and navigates the browser to the dedicated blocked page at
`/_waf/blocked` (configurable with `LARAVEL_WAF_BLOCKED_PATH`). This keeps the
blocked page at a normal top-level URL instead of displaying the HTML response
inside Livewire's error modal.
