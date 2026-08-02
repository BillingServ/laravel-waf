# Security Policy

## Scope

This repository contains a Laravel package and an optional Linux ipset decision agent. It does not provide upstream or volumetric DDoS mitigation.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use the repository's private security advisory process or contact the maintainers through the security contact published for the project.

Include the affected version or commit, deployment assumptions, reproduction steps, and impact. Please redact credentials, personal data, and live attack targets.

## Design boundaries

- The Laravel package must never require root privileges.
- The agent must validate every decision, enforce expiration, and use argument arrays rather than a shell.
- Request signatures are bounded and configurable; they are not a substitute for parameterized queries, output encoding, or safe file APIs.
- GeoIP enforcement must use a trusted local database or an application-provided resolver; an unavailable resolver fails open unless explicitly configured otherwise.
- Metrics must not contain unbounded or sensitive request data.
- Notifications must never receive raw request bodies, query strings, credentials, or headers.
- Upstream DDoS protection remains the responsibility of the hosting provider or network operator.
