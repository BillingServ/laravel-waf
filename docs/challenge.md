# Challenge mode

Challenge mode is an application-layer control for clients that exceed the
configured request limits. It is not a replacement for Nginx, iptables, or
upstream DDoS protection.

## ALTCHA with the existing bsv211 endpoint

The package reads the existing bsv211 variables by default:

```dotenv
LARAVEL_WAF_PRESET=balanced
LARAVEL_WAF_SECRET=replace-with-one-random-64-character-hex-secret

ALTCHA_CHALLENGE_URL=https://example.test/altcha/challenge
```

Install the package as normal. The official ALTCHA PHP library is installed
as a package dependency and is used to verify the submitted payload. Configure
the challenge-generating endpoint with the same `LARAVEL_WAF_SECRET` value. The
legacy custom endpoint should return a fresh, short-lived challenge and must
not be cached.

WAF-specific variables can override the shared secret and application variables
when the application has more than one ALTCHA integration:

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

The `balanced` preset uses an automatic Anubis-style proof-of-work
interstitial. These granular values remain available when the text or widget
behaviour needs to differ from the preset:

```dotenv
LARAVEL_WAF_CHALLENGE_TITLE="Checking your browser"
LARAVEL_WAF_CHALLENGE_MESSAGE="This usually takes only a few seconds."
LARAVEL_WAF_ALTCHA_AUTO=onload
LARAVEL_WAF_ALTCHA_AUTO_SUBMIT=true
LARAVEL_WAF_ALTCHA_DISPLAY=invisible
LARAVEL_WAF_CHALLENGE_COOKIE_TTL=3600
```

The widget starts on page load and submits the verification form as soon as
ALTCHA reports a verified proof. In automatic invisible mode, both the widget
and manual control stay concealed while the page shows a live progress state.
A reload action appears only if verification takes too long or fails. If
ALTCHA explicitly requests an interactive challenge, the widget is revealed so
the visitor is not trapped. Non-automatic integrations retain the visible
Continue button.

`LARAVEL_WAF_ALTCHA_CHALLENGE_ATTRIBUTE` may be `challengeurl` for the
existing widget integration or `challenge` for newer widget integrations.
The challenge field and script URL are configurable so the WAF does not need
to own the application's frontend setup.

The visitor-facing verification and blocked pages do not display the package
name. They use a small BillingServ security attribution and include an opaque
request ID that is also returned in the `X-Request-ID` response header.

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
4. The browser is redirected to the original GET/HEAD URL, or to the same-origin
   referring form page when the challenged request changed state.
5. The challenge cookie receives a separate bounded rate limit; it is not an
   unlimited bypass.

The internal verification route is exempt from the ordinary request limiter,
but it has its own per-IP verification limit. Keep it protected by the Nginx
limits described in [`nginx-ddos.md`](nginx-ddos.md).

Livewire update requests that are challenged receive a successful Livewire
redirect to the dedicated challenge page at `/_waf/challenge`. This keeps the
verification document out of the current component or modal. Because a
state-changing request must not be replayed with credentials, verification
returns to the page that sent the request. Keep `laravel-waf.login` attached to
credential endpoints: generic DDoS limits still apply there, but an exhausted
bucket returns a plain `429` instead of replacing the submitted credentials
with a browser challenge. Package-owned browser redirects and form actions use
same-origin relative URLs while retaining the request's application base path,
so a different configured `APP_URL`, tenant host, proxy origin, or subdirectory
mount cannot detach the flow from the current Laravel session.

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

The trigger is disabled by default. Enabling `LARAVEL_WAF_TESTING_ENABLED`
activates it in every environment, including production, so disable it again
after checking the deployed page. The parameter name and an optional required
value are configurable with `LARAVEL_WAF_TESTING_PARAMETER` and
`LARAVEL_WAF_TESTING_VALUE`.

The trigger returns a `403` blocked response and never issues a challenge
token or verification cookie. It is intended for checking the blocked state
of the page; normal challenge behavior is still exercised by exceeding the
configured limit.

## Livewire and Filament

Livewire form submissions are handled as JSON requests. When request
inspection blocks a Livewire update, the package returns Livewire's successful
redirect response shape and navigates the browser to the dedicated blocked
page at `/_waf/blocked` (configurable with `LARAVEL_WAF_BLOCKED_PATH`). This
loads the same top-level blocked page used by Nginx instead of rendering a
fragment inside the authenticated application layout.
