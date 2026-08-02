# laravel-waf-agent

`laravel-waf-agent` is an optional Linux service for the Laravel WAF. It receives high-confidence, short-lived IP block decisions over a local Unix socket and updates administrator-created `ipset` sets.

It intentionally does not:

- load XDP/eBPF programs;
- modify iptables rules automatically;
- inspect HTTP or TLS traffic;
- expose a network control API;
- require the Laravel PHP process to have root privileges.

## Build and test

```bash
go test ./...
go build -o bin/laravel-waf-agent ./cmd/laravel-waf-agent
```

The agent is Linux-only because it invokes `ipset`.

## Firewall preparation

Create the sets and attach them to the input chain as an administrator. The agent can create the sets, but it does not create firewall rules:

```bash
sudo ipset create laravel_waf_block_v4 hash:ip family inet timeout 86400 -exist
sudo ipset create laravel_waf_block_v6 hash:ip family inet6 timeout 86400 -exist

sudo iptables -C INPUT -m set --match-set laravel_waf_block_v4 src -j DROP \
  || sudo iptables -I INPUT -m set --match-set laravel_waf_block_v4 src -j DROP
sudo ip6tables -C INPUT -m set --match-set laravel_waf_block_v6 src -j DROP \
  || sudo ip6tables -I INPUT -m set --match-set laravel_waf_block_v6 src -j DROP
```

Review these rules for the host's existing firewall policy before applying them. Persist the sets and rules using the operating system's normal firewall tooling.

## Run

```bash
sudo ./bin/laravel-waf-agent \
  --socket /run/laravel-waf/agent.sock \
  --socket-group www-data \
  --secret-file /etc/laravel-waf/agent.secret
```

The socket group must match the PHP-FPM process group. The secret file is optional but recommended. It must match `LARAVEL_WAF_AGENT_SECRET` in the Laravel application. The metrics listener binds to loopback by default at `127.0.0.1:9919`.

Use `--dry-run` while validating the integration. Start with `LARAVEL_WAF_AGENT_AUTO_BLOCK=false`; automatic host blocks should only be enabled after the application's IP and proxy configuration have been verified.

## Safety model

The protocol accepts only `block_ip` and `unblock_ip`, validates IP addresses and TTLs, limits reason values, and uses argument arrays when invoking `ipset`. A stale block expires in the ipset; the agent does not maintain permanent blocks.
