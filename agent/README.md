# laravel-waf-agent

`laravel-waf-agent` is an optional Linux service for the Laravel WAF. It receives high-confidence, short-lived IP block decisions over a local Unix socket, updates expiring `ipset` sets, and attaches those sets to TCP ports 80 and 443 in the host INPUT chains. An opt-in second Unix socket can act as an Nginx traffic-pressure gate before PHP.

By default it intentionally does not:

- load XDP/eBPF programs;
- inspect HTTP or TLS traffic;
- expose a network control API;
- require the Laravel PHP process to have root privileges.

Gate mode does inspect only the request metadata explicitly forwarded by Nginx:
the client IP, original URI and method, and cookies. It does not render CAPTCHA
pages or process ALTCHA proofs. Laravel retains those responsibilities.

## Build and test

```bash
go test ./...
go build -o bin/laravel-waf-agent ./cmd/laravel-waf-agent
```

The agent is Linux-only because it invokes `ipset`.

## Firewall lifecycle

By default the agent creates its IPv4 and IPv6 sets and ensures that one static
`iptables`/`ip6tables` INPUT rule references each set. It checks the rules before
every block decision and every 30 seconds, restoring them if another firewall
service has flushed them.

Accepted block decisions are also recorded in
`/var/lib/laravel-waf/blocks.json`. The record contains the normalized IP, the
bounded reason from the decision, and its expiry time. The file is an audit and
display ledger; `ipset` remains authoritative for enforcement.
If the ledger cannot be initialized or updated, the agent logs a warning and
continues enforcing successful firewall operations. `list-ip` may be incomplete
until the state-file problem is corrected.

On upgrade, the agent removes the legacy set rules that dropped all incoming
traffic before installing the web-only rules.

The static rules do not contain individual addresses or timeouts. A block adds
the address to the appropriate set with its requested TTL; the kernel removes
that member automatically when the TTL expires. You can inspect the resulting
state with:

```bash
sudo ipset list laravel_waf_block_v4
sudo iptables -C INPUT -p tcp -m multiport --dports 80,443 -m set --match-set laravel_waf_block_v4 src -j DROP
sudo ip6tables -C INPUT -p tcp -m multiport --dports 80,443 -m set --match-set laravel_waf_block_v6 src -j DROP
```

The managed rules drop only TCP traffic to ports 80 and 443. SSH, ICMP, and
other services remain reachable. Change the comma-separated ports with
`--block-tcp-ports`, or use `--manage-iptables=false` when another firewall
manager owns these rules. Set `--firewall-reconcile-interval=0` to disable only
the periodic check.

## Run

```bash
sudo ./bin/laravel-waf-agent \
  --socket /run/laravel-waf/agent.sock \
  --socket-group www-data \
  --secret-file /etc/laravel-waf/agent.secret
```

The socket group must match the PHP-FPM process group. The secret file is optional but recommended. It must match `LARAVEL_WAF_AGENT_SECRET` in the Laravel application. The metrics listener binds to loopback by default at `127.0.0.1:9919`; the Laravel `/prometheus` endpoint can collect it so Prometheus needs only one protected scrape target.

Use `--dry-run` while validating the integration. Start with `LARAVEL_WAF_AGENT_AUTO_BLOCK=false`; automatic host blocks should only be enabled after the application's IP and proxy configuration have been verified. When the host also runs a firewall service that rebuilds INPUT, order this service after it so the initial rules are attached last.

## Manually add or remove an IP

The running agent can also accept explicit operator decisions through its
existing Unix socket. Add an IPv4 or IPv6 address to the block set by providing
a duration in seconds or Go duration notation (`15m`, `2h`, or `24h`):

```bash
sudo laravel-waf-agent add-ip 203.0.113.10 15m
```

Add a reason with `--reason` (use letters, numbers, `_`, `.`, `:`, or `-`, up
to 64 characters):

```bash
sudo laravel-waf-agent add-ip --reason manual_review 203.0.113.10 15m
```

Remove it before the duration expires with:

```bash
sudo laravel-waf-agent remove-ip 203.0.113.10
```

List active blocks and the reasons that were recorded when they were added:

```bash
sudo laravel-waf-agent list-ip
```

Use `--json` for scripts. If the daemon uses a non-default state file, pass the
same path with `--state-file` to `list-ip` and as a daemon option. Expired
records are omitted from the list and are pruned from the file on the next
block update. Blocks inserted directly with `ipset` are not in the agent ledger
and do not have an agent reason.

The `add-ip` and `remove-ip` commands use `/run/laravel-waf/agent.sock` by
default. Pass
`--socket /another/path.sock` before the IP when the service uses a different
socket. They automatically read `/etc/laravel-waf/agent.secret`; use
`--secret-file /another/path` only when the running service uses a different
secret file. For a service configured without HMAC authentication, pass
`--secret-file=`. A block can last from one second to 24 hours, and may be
further limited by the service's `--max-ttl` setting. Adding an existing address
updates its expiry and reason. Removing an address is safe even if it has
already expired.

## Optional pre-application gate

Gate mode is enabled only when `--gate-socket` is set:

```bash
sudo ./bin/laravel-waf-agent \
  --socket /run/laravel-waf/agent.sock \
  --socket-group www-data \
  --secret-file /etc/laravel-waf/agent.secret \
  --gate-socket /run/laravel-waf/gate.sock \
  --gate-socket-group www-data \
  --gate-threshold 600 \
  --gate-window 60s \
  --challenge-secret-file /etc/laravel-waf/challenge.secret \
  --gate-token-file /etc/laravel-waf/gate-token.secret
```

The challenge secret must exactly match
`LARAVEL_WAF_CHALLENGE_COOKIE_SECRET`. The gate token must exactly match
`LARAVEL_WAF_AGENT_GATE_TOKEN`. Both must contain at least 32 bytes.

Only `GET` and `HEAD` are challenged by default. Other methods contribute to
traffic pressure but continue to Laravel, where the normal WAF limits still
apply. This avoids losing or automatically replaying a form submission.

See [`../docs/agent-gate.md`](../docs/agent-gate.md) for the required Nginx
configuration and rollout procedure.

## Safety model

The firewall decision protocol still accepts only `block_ip` and `unblock_ip`, validates IP addresses and TTLs, limits reason values, and uses argument arrays when invoking `ipset`, `iptables`, and `ip6tables`. A stale block expires in the ipset; the agent does not maintain permanent IP members.

The gate listens on a separate Unix socket. Nginx is the only intended client.
Invalid gate metadata is rejected, bypass paths are bounded, pass cookies are
HMAC-verified and IP-bound, and challenge responses carry an authenticated
marker that Laravel validates before rendering a page.
