# IP reputation without rebuilding LWAFD

The standalone Python helper downloads public reputation feeds and loads
separate IPv4/IPv6 `hash:net` ipsets. It blocks listed IPs and CIDRs on TCP
ports 80 and 443 before Laravel runs, including signup and login. Laravel's
`rules.mode=log`, challenge cookies, and the agent's automatic-ban settings
do not affect these firewall rules. The installed Go binary is unchanged.

The default sources are:

| Source | IPv4 | IPv6 | Coverage |
| --- | --- | --- | --- |
| [Tor Project exit list](https://check.torproject.org/exit-addresses) | Yes | No | Observed Tor exit addresses |
| [Tor Onionoo](https://metrics.torproject.org/onionoo.html) | Via the exit list | Yes | Advertised IPv6 addresses of running exit relays permitting TCP 80 or 443, plus observed IPv6 exit addresses when supplied |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Yes | Yes | Separate feeds for networks controlled by criminal operations |
| [blocklist.de](https://www.blocklist.de/en/export.html) | Yes | Yes | Addresses reported for attacks within the last 48 hours |
| [FireHOL Level 2](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset) | Yes | No | Recent attacks, combining blocklist.de, DShield, and GreenSnow |

To share your own blocks, connect a private
[BSRBL registry](bsrbl.md). The helper downloads its authenticated JSON feed;
with the updated Go agent, bans are reported directly. Python only downloads
and applies feeds by default; existing cron commands need no changes. Direct
reporting needs a one-time binary update, without an additional service or
Ansible deployment. Manual Python backfills require `--report-only`. No attack
logs are submitted.

The Tor exit list alone does not cover IPv6. The `tor_ipv6` source supplements
it with Onionoo relay data. Onionoo currently measures IPv4 exit addresses;
its IPv6 relay addresses are associated with exits, rather than measured IPv6
egress addresses. Relays can use an unadvertised address for outbound traffic,
so this does not guarantee every possible Tor IPv6 exit is listed. Each IPv6
address is imported as an exact `/128`, rather than blocking its whole subnet.

FireHOL Level 2 is IPv4-only. The direct blocklist.de feed adds IPv6 abuse
reports alongside it. All feeds accept IPv4/IPv6 entries when supplied, and
refresh logs show counts for both address families.

Only FireHOL's published data is consumed; installing FireHOL is unnecessary.
These feeds do not enumerate every VPN, residential proxy, or attacker. They
add reputation blocking alongside the existing WAF rules and rate limits.
Spamhaus Project supplies the DROP data; cached source files preserve its
copyright, provider metadata, and dates. Review the providers' linked terms.

## Run on the Linux ingress host

Requirements: Python 3.8+, `ipset`, `iptables`, and `ip6tables`. No Python
packages or Go compiler are required. The helper ships in the Composer package,
so run it directly from your application's `vendor` directory. Replace
`/var/www/your-app` with your application's absolute path:

```bash
python3 /var/www/your-app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py --dry-run
sudo /usr/bin/python3 /var/www/your-app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py
```

The second command activates blocking immediately. Each `composer update`
updates the helper in `vendor`; copying it into `/usr/local` is unnecessary.
For deployments with release directories, use the stable `current` symlink
in the commands and cron entries below.

## Add your cron job

Open root's crontab with `sudo crontab -e` and add the following lines, replacing
the application path. These are root crontab entries, so there is no username
column:

```cron
17 * * * * /usr/bin/python3 /var/www/your-app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
@reboot /bin/sleep 30 && /usr/bin/python3 /var/www/your-app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
```

The first entry refreshes the lists hourly at minute 17. The second restores
them shortly after reboot, since kernel ipsets do not survive a reboot. You
control the schedule; the package does not install or modify cron entries.
The cron daemon must be installed and running on the host.

Failed refreshes exit with a nonzero status and write errors to the log; any
usable cached feeds continue to be enforced. Check the schedule and results:

```bash
sudo crontab -l
sudo tail -n 50 /var/log/lwaf-reputation.log
sudo ipset list lwaf_reputation_v4
sudo ipset list lwaf_reputation_v6
```

The helper stages complete lists and then swaps each live set. CIDRs remain
CIDRs. It never changes `laravel_waf_block_v4`, `laravel_waf_block_v6`, or the
agent's block ledger, so `lwafd list-ip` continues to show dynamic/manual bans
only. Refreshing also restores missing reputation INPUT rules. A firewall
reload can leave those rules absent until the next helper run; run the helper
manually after reloading a firewall.

Downloaded feeds are validated before replacing cached data. Failed downloads,
invalid content, and empty lists use the previous cache for up to 48 hours.
Kernel members retain the original cache expiry, so a failed refresh cannot
extend a stale block indefinitely. Expired feeds are omitted at the next run.

## Check IPv4 and IPv6 enforcement

Verify that both sets contain entries and both firewall rules are present:

```bash
sudo ipset list lwaf_reputation_v4 -terse
sudo ipset list lwaf_reputation_v6 -terse
sudo iptables -L INPUT -n -v | grep lwaf_reputation
sudo ip6tables -L INPUT -n -v | grep lwaf_reputation
```

For an individual address, use `ipset test` with the matching family and also
check its allowlist. For example, replace `YOUR_IPV6_ADDRESS` below:

```bash
sudo ipset test lwaf_reputation_v6 YOUR_IPV6_ADDRESS
sudo ipset test lwaf_rep_allow_v6 YOUR_IPV6_ADDRESS
```

An address must match the reputation set and be absent from its allowlist for
that firewall rule to drop it. A matching set entry alone does not prove a
request was blocked: verify packet counters and use the actual source address
for the protected site. Tor can use different exit relays for different sites.

## Exceptions and feed selection

Add options to the helper command in both cron entries and in manual runs.
For example, to exempt an operational address and a monitoring network:

```bash
sudo /usr/bin/python3 /var/www/your-app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py --allow-ips=203.0.113.10,100.64.0.0/10
```

Replace the example addresses with your own. Include the agent's
`--metrics-allowed-ips` sources here if they must bypass reputation drops too;
the helper has its own allowlist. These exceptions affect reputation lists
only; they do not override the agent's temporary bans.

`--feeds=tor,tor_ipv6,blocklist_de,spamhaus_drop_v4,spamhaus_drop_v6,firehol_level2`
selects the default sources. Selecting `tor` also enables `tor_ipv6`, including
for existing cron commands that explicitly set `--feeds=tor`. Remove other
names to disable specific feeds. `--max-age=172800`
sets the cache lifetime in seconds, bounded between two hours and seven days.
`--ports=80,443` changes the protected TCP ports without touching SSH or other
services. Pass `--ipset`, `--iptables`, or `--ip6tables` if executables are
installed outside `/usr/sbin`.

## Traffic forwarded by another proxy

The kernel sees the network peer. If a different machine proxies traffic to
this host, put the helper on that ingress machine, or enable the optional
Nginx check below. Loading the public client's IP into the backend firewall
cannot match a packet whose source is the proxy.

To reject forwarded clients locally without changing the agent, create an
empty include after the first helper run:

```bash
sudo install -m 0644 /dev/null /var/lib/laravel-waf/reputation/nginx.geo
```

Add this in Nginx's `http` context:

```nginx
geo $remote_addr $lwaf_reputation_blocked {
    default 0;
    include /var/lib/laravel-waf/reputation/nginx.geo;
}
```

Add this in each protected `server` block:

```nginx
if ($lwaf_reputation_blocked) {
    return 403;
}
```

Configure Nginx's real IP module to trust only your actual ingress proxy
addresses so `$remote_addr` is the verified client IP. Never use an unchecked
forwarding header as the lookup address. Test and reload this initial Nginx
configuration, then add the following option to the helper in both cron entries
and in manual runs:

```text
--nginx-geo-file=/var/lib/laravel-waf/reputation/nginx.geo
```

Keep any `--allow-ips` options in the same command. Each update regenerates
the include, runs `nginx -t`, and reloads Nginx only when the include changes.
Failed configuration checks restore the previous include. The generated data
applies allowlist exceptions even inside a blocked network. This Nginx check
rejects every HTTP method, including signup/login POSTs, before PHP or CAPTCHA
handling. Keep the cron job active: Nginx entries have no native timeout and are
removed when the helper next updates the include.

## Disable reputation blocking

Remove the two reputation entries with `sudo crontab -e`. Let any active
refresh finish, then clear the reputation sets:

```bash
sudo ipset flush lwaf_reputation_v4
sudo ipset flush lwaf_reputation_v6
```

The empty sets leave their INPUT rules harmless. If using the Nginx check,
also empty its generated include, test, and reload Nginx. The agent's normal
bans and firewall rules remain active.

## Development

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s agent/scripts -p 'test_*.py'
```
