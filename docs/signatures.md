# Signatures (virtual patching)

Signatures are operator-managed request rules stored in JSON files on the
server. They let you block a new exploit within seconds of it appearing,
without deploying the application or rebuilding the agent.

The same files are enforced in two places:

| Layer | Sees | When it reloads |
| --- | --- | --- |
| LWAFD gate (`--signatures`) | method, path, query, headers | every 5s, or immediately on `SIGHUP` |
| Laravel (`laravel-waf.signatures`) | the above, plus the parsed body | every 5s per PHP worker |

The gate stops a request before PHP starts. Laravel is the fallback when
the gate is not deployed, and the only place `body` rules run.

## Built-in rules

`resources/rules/core.json` ships with the package and covers scanner
traffic seen in production: PHP-CGI argument injection (CVE-2024-4577),
PHP stream wrappers, `/proc/self/` and system-file probes, shell payloads in
URLs, `.env`/`.git` probes, `/cgi-bin/`, Vite `@fs` probes, and known
exploit-scanner user agents. These rules **ban** the client for 24 hours.
WordPress, foreign-script, `phpinfo`, and traversal probes are **blocked**
without a ban.

Laravel loads it automatically (`LARAVEL_WAF_SIGNATURES_BUILTIN=true`). Point
the gate at the installed copy so a `composer update` refreshes both layers:

```text
--signatures /etc/laravel-waf/rules.d,<application-root>/vendor/billingserv/laravel-waf/resources/rules/core.json
```

## Adding a rule during an incident

1. Write a file in `/etc/laravel-waf/rules.d/` (files load in name order):

   ```json
   {
       "version": 1,
       "rules": [
           {
               "id": "cve-2026-12345",
               "description": "Exploit for vulnerable export endpoint",
               "action": "ban",
               "ttl": 86400,
               "conditions": [
                   {"target": "path", "op": "prefix", "value": "/admin/export"},
                   {"target": "query", "op": "contains", "values": ["../", "php://"]}
               ]
           }
       ]
   }
   ```

2. Validate it, and check what a request would hit:

   ```bash
   lwafd check-signatures /etc/laravel-waf/rules.d
   lwafd match-signatures --method POST '/admin/export?file=../../.env'
   ```

3. Reload the gate now (Laravel workers pick it up within 5 seconds):

   ```bash
   sudo systemctl kill -s HUP lwafd
   ```

If a file becomes invalid, both layers keep enforcing that file's last valid
version and report the error (agent log, `laravel_waf_agent_signature_reloads_total{outcome="error"}`,
and the Laravel log). Laravel retains valid documents in its configured cache
store: use a persistent driver such as file, database or Redis for PHP-FPM.
Clearing that cache also clears the saved versions. If PHP cannot load a rule
or recover a valid version, it returns 503 rather than silently skipping it.
The agent retains versions in daemon memory; validate files before restarting it.

An unavailable configured file or directory retains its previous rules.
Deleting a drop-in from a directory that can still be listed removes that
file's rules as intended. Publish updates with an atomic rename after validation.

## Format

```json
{
    "version": 1,
    "disable": ["wordpress-probe"],
    "rules": [ ... ]
}
```

`disable` switches off any rule by ID, including built-in ones, from any file.

| Rule field | Meaning |
| --- | --- |
| `id` | Required. `[a-z0-9][a-z0-9_.-]`, at most 32 characters. Used in metrics and ban reasons. |
| `action` | `block` (default) denies the request. `ban` also adds a firewall block for `ttl` seconds. `log` only records a metric and log entry. |
| `ttl` | Ban length in seconds, 1–86400. Default 3600. |
| `enabled` | `false` keeps a rule in the file without enforcing it. |
| `conditions` | 1–16 conditions; **all** must match. Write separate rules for "or". |

| Condition field | Meaning |
| --- | --- |
| `target` | `method`, `path`, `query`, `user_agent`, `header:<name>`, `body`, or a list of these (any may match). |
| `op` | `equals`, `prefix`, `suffix`, `contains`, or `regex`. |
| `value` / `values` | One string, or a list where any may match. `regex` takes exactly one. |
| `negate` | `true` inverts the condition, for example to exempt a path. |

Matching is case-insensitive. Before matching, `path` is URL-decoded twice
(`%252e` → `.`), and `query` is the whole raw query string URL-decoded twice
with `+` as a space. That catches payloads hidden in parameter *names*, such
as `?-d+allow_url_include=1`. Header and user-agent values are not decoded.
A missing header matches `"equals": ""`.

Regexes use [RE2 syntax](https://github.com/google/re2/wiki/Syntax), with no
lookaround or backreferences. Go evaluates them with RE2; PHP uses PCRE.
A PHP matching error (including its backtracking limit) returns 503 for an
enforcing rule and never dispatches a ban. A log-only rule remains an
observation even when its match cannot be determined.

`body` conditions only run inside Laravel. They match each parsed body value
and unusual parameter name after URL and HTML-entity decoding. The gate skips
any rule that uses `body`.

## Laravel configuration

```dotenv
LARAVEL_WAF_SIGNATURES_ENABLED=true
LARAVEL_WAF_SIGNATURES_BUILTIN=true
LARAVEL_WAF_SIGNATURE_PATHS=/etc/laravel-waf/rules.d
LARAVEL_WAF_SIGNATURES_RELOAD_INTERVAL=5
```

`ban` needs `LARAVEL_WAF_AGENT_ENABLED=true`. Without the agent, a ban is
enforced as a block. Signature bans apply even when
`LARAVEL_WAF_AGENT_AUTO_BLOCK_ON_FINDING=false`, because the rule states the
intent. `block` signatures never trigger the generic auto-block.
Signature actions also override the generic request-rules mode. To observe
before enforcing, use `action: "log"` in your rules and disable the built-ins
until you are ready for their configured bans.

`WafProtection` is route-group middleware, so it never runs for URLs with no
route. Most scanner traffic is in that group (404s and 405s). To evaluate
signatures for those requests in Laravel as well, register the lightweight
global middleware:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(\BillingServ\LaravelWaf\Http\Middleware\SignatureProtection::class);
})
```

Run it after `TrustProxies` so bans use the resolved client IP, while still
running before routing for 404/405 coverage. It marks each request it checks, so `WafProtection` never reports or bans
the same request twice.

## Metrics

```text
laravel_waf_agent_signature_matches_total{rule="...",action="ban|block|log"}
laravel_waf_agent_signature_reloads_total{outcome="loaded|unchanged|error"}
laravel_waf_agent_signature_rules
laravel_waf_agent_gate_requests_total{outcome="signature_banned|signature_blocked|signature_ban_error"}
laravel_waf_findings_total{category="signature",rule="...",action="reject|log"}
```
