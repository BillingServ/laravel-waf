# Security Policy

## Scope

This repository contains a Laravel package and an optional Linux ipset decision agent. It does not provide upstream or volumetric DDoS mitigation.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use the repository's private security advisory process or contact the maintainers through the security contact published for the project.

Include the affected version or commit, deployment assumptions, reproduction steps, and impact. Please redact credentials, personal data, and live attack targets.

## Design boundaries

- The Laravel package must never require root privileges.
- The agent must validate every decision, enforce expiration, and use argument arrays rather than a shell.
- Metrics must not contain unbounded or sensitive request data.
- Upstream DDoS protection remains the responsibility of the hosting provider or network operator.
