# Laravel security coverage

Laravel WAF is an application-layer control. It can reject or challenge a
request, but it cannot prove that an application's authorization rules,
database queries, deployment, or business logic are correct.

The table uses the OWASP Top 10:2025 categories as a planning guide:

| Area | Controls in this package | Still required in the Laravel application or deployment |
| --- | --- | --- |
| A01 Broken Access Control | Named route policies, method checks, required middleware checks, and request telemetry | Gates, Policies, scoped queries, tenant checks, and tests for every sensitive action |
| A02 Security Misconfiguration | Standard response headers, optional HSTS, route policy checks, and bounded metrics | Trusted hosts and proxies, production debug settings, secure storage, Nginx configuration, and patching |
| A03 Software Supply Chain Failures | No runtime dependency substitution or code loading | Composer audit, locked dependencies, package review, CI controls, and deployment integrity |
| A04 Cryptographic Failures | Secure challenge cookies and optional HSTS for HTTPS responses | TLS, `APP_KEY`, session cookie settings, secret rotation, and correct encryption choices |
| A05 Injection | XSS, SQL injection, RFI, LFI, command, template, NoSQL, LDAP, CRLF, and SSRF signatures | Parameterized queries, output encoding, safe file APIs, validation, and framework-specific escaping |
| A06 Insecure Design | Route limits, behavior tracking, login protection, and browser challenges | Abuse limits for each workflow, replay protection, transaction rules, and safe defaults |
| A07 Authentication Failures | Login middleware, Laravel authentication event hooks, IP and identifier limits, notifications, and optional agent blocks | Password reset protection, MFA, session rotation, token expiry, account recovery, and credential storage |
| A08 Software and Data Integrity Failures | Route middleware checks and signed challenge state | Signed webhooks, upload validation, deployment signing, trusted queues, and integrity checks |
| A09 Security Logging and Alerting Failures | Redacted findings, cooldown notifications, Prometheus metrics, and behavior events | Central log retention, alert routing, incident response, access reviews, and clock synchronization |
| A10 Mishandling Exceptional Conditions | Input caps, rate limiter failure modes, generic block responses, and bounded challenge attempts | Nginx timeouts, PHP worker limits, safe exception handling, transaction cleanup, and load testing |

## Behavior protection

The middleware counts response classes by client IP in the configured cache
store. Repeated 404, 405, 401, 403, or other 4xx responses can produce a
finding. The default action is a challenge when challenges are enabled, and a
block otherwise. Thresholds should be adjusted for applications that expose
large public collections of missing URLs or return many normal 4xx responses.

Use Redis or another shared cache when more than one application worker or
server handles traffic. The counters contain hashed keys and do not store
request bodies or URLs.

## Response headers

`WafProtection` adds `X-Content-Type-Options`, `X-Frame-Options`, and
`Referrer-Policy` when they are not already present. Content Security Policy,
Permissions Policy, and HSTS are configurable. HSTS is only added when
Laravel considers the request secure. Test a policy against the application
before enabling it globally.

## What it cannot do

- It does not absorb volumetric or network-level DDoS attacks.
- It does not replace Laravel authentication, authorization, validation, or
  database protections.
- It does not inspect encrypted traffic before Nginx or inspect arbitrary
  binary upload content.
- It does not automatically wrap every outbound HTTP client request.
- It does not identify every zero-day or business-logic abuse case.

Use Nginx, iptables, the optional agent, host monitoring, and an upstream
provider alongside the package.
