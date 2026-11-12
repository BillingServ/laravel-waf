# BSRBL reporting and shared blocks

BSRBL at `https://rbl.bserv.uk` has two integrations:

| Component | Request | When |
| --- | --- | --- |
| Existing Go agent | `POST /api/v1/reports` | After a local firewall ban succeeds |
| Python reputation helper | `GET /api/v1/feed` | On the download cron schedule |

Direct reporting covers Go gate signatures/rate limits, signed Laravel bans, and manual `add-ip` decisions. It runs in the existing agent, with no additional service. This requires a one-time Go binary update and restart; no Ansible deployment is needed.

## One-time agent update

Build the updated binary with `./agent/build.sh` (Linux amd64 by default; set `GOARCH=arm64` for ARM servers). Upload the correct binary to each node. Replace the installed binary atomically, keeping all existing service arguments:

```sh
sudo install -m 0755 /tmp/lwafd.new /usr/local/bin/lwafd.new
sudo mv /usr/local/bin/lwafd.new /usr/local/bin/lwafd
```

Use your actual installed binary path/name if different. No extra unit files or services are required.

## Use the existing Laravel .env

On the BSRBL hosting account, create a separate key for each WAF server:

```sh
php bin/console key:create --name=server-1 --scopes=read,report --days=0
```

Keep the BSRBL settings in the WAF application's existing Laravel `.env`:

```dotenv
LARAVEL_WAF_BSRBL_URL=https://rbl.bserv.uk
LARAVEL_WAF_BSRBL_API_KEY=the-key-for-this-server
LARAVEL_WAF_BSRBL_REPORT_ENABLED=true
```

Then restart the existing agent once to load the updated binary:

```sh
sudo systemctl restart lwafd
sudo journalctl -u lwafd -n 50 --no-pager
```

Go discovers `<application-root>/.env` from the Composer package path already configured in `--signatures`, for example `/home/bsv3/vendor/billingserv/laravel-waf/resources/rules/core.json`. No new configuration file or template is needed. It re-reads only the BSRBL settings, so key, URL and report-enable changes need no rebuild or restart. Other Laravel secrets are ignored, and no shell execution or variable interpolation occurs. Process environment values override file values.

If the binary itself is inside the Composer package, its path can identify the application too. Otherwise a working directory inside a Laravel application (identified by `artisan` and `composer.json`) is a fallback. The agent never scans other applications' directories. Multiple Composer application roots require an explicit choice: `--bsrbl-env-file=/absolute/path/to/.env`. This flag also supports unusual layouts. The startup log shows the selected configuration path, never its contents.

The service must be able to read the application's `.env`. An application under `/home` needs the same read-only service access used for Composer signatures; see the [existing signature setup](signatures.md#built-in-rules). If only the package directory is exposed, expose the application root instead. `ProtectHome=true` can otherwise hide `.env` from Go. This can be configured directly on the host without Ansible or an additional service.

`--bsrbl-state-file=/absolute/path` optionally overrides the private outbox path. The default uses the existing service's writable state directory. A missing configuration file leaves direct reporting disabled. `REPORT_ENABLED=false` pauses queued delivery and stops capturing new reports. Keys need `read,report` permissions; a read-only key cannot submit bans.

## Keep the existing download cron

Deploy the updated Python helper. Downloads are now the default, so existing cron entries need no changes or extra flags. For example:

```cron
17 * * * * /usr/bin/python3 /home/bsv3/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
@reboot /bin/sleep 30 && /usr/bin/python3 /home/bsv3/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
```

Adjust `/home/bsv3` on other nodes. Keep any existing `--allow-ips`, `--ports`, or `--nginx-geo-file` options. Remove a minute-by-minute `--report-only` cron entry if you previously added one.

The Go agent now calls the reporting API automatically after a ban, normally immediately for an idle reporter. HTTP work runs in the background and never waits for the next cron. Other servers still apply a new shared block on their next scheduled feed download.

## Delivery and failure behaviour

The local firewall is updated first. Failed firewall operations and unblock operations do not create reports. Network calls use a five-second timeout, HTTPS certificate verification, a Bearer header and no redirects. The payload contains only IP, reason and `expires_at: null`; no request/attack logs are sent. Reasons are public on the BSRBL lookup page.

Reports are durably queued at `/var/lib/laravel-waf/bsrbl-report-outbox.json` with owner-only permissions. API failures retry in the same agent after about a minute, including after the local ban expires or the agent restarts. Queued delivery is paced to stay below the API's per-key rate limit, so bursts may wait. Successful responses are deduplicated; excluded/protected entries are acknowledged without re-adding them. A local unblock does not revoke a report already accepted by BSRBL; exclude it in BSRBL when a shared block should be removed.

The outbox is bounded to 10,000 pending entries and a 16 MiB state file. Storage/capacity errors are logged while the local firewall decision remains accepted. Corrupt delivery state is not silently reset. One agent owns each outbox; custom multiple-agent installations need distinct state paths. Changing the destination URL starts a separate delivery history rather than sending old queued reports to another host.

All reports accepted by the updated BSRBL service are permanent until an administrator excludes them. Local agent TTLs remain unchanged. Shared entries are not written to the local agent's block ledger, preventing report loops.

## Downloads and manual backfill

The helper merges BSRBL with the existing public feeds and applies IPv4/IPv6 reputation sets. A valid empty private feed clears this source. Failed downloads retain a usable private cache for at most `--max-age` (48 hours by default); finite manually timed entries keep their original expiry. Fresh hourly downloads keep permanent entries enforced. Default protected TCP ports are 80/443.

```sh
# Validate downloads without changing firewall rules or submitting reports.
sudo /usr/bin/python3 /home/bsv3/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py --dry-run

# Optional one-off backfill of active local bans; no download/firewall refresh.
sudo /usr/bin/python3 /home/bsv3/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py --report-only
```

Normal runs only download and apply feeds, including when `LARAVEL_WAF_BSRBL_REPORT_ENABLED=true` is set for Go. Reporting from Python requires an explicit `--report-only` invocation and includes only bans still active when it runs. `--download-only` remains accepted for compatibility, but is optional and cannot be combined with `--report-only`. Older Go binaries need updating for automatic reporting; the normal Python run no longer submits bans. The helper also reads the existing Laravel `.env` automatically for Composer installations. If the helper is copied outside the Composer package, pass `--env-file=/absolute/path/to/.env` to select the same application as Go.

## Permanent-report policy and Cloudflare

Deploy the updated BSRBL app files (`src/bootstrap.php`, `public/index.php`, `src/view.php`, `bin/console`) and run `php bin/console policy:apply` on its hosting account. This makes retained service reports permanent, including previously expired reports, and excludes old Cloudflare proxy entries. Existing administrator exclusions and explicitly timed manual blocks remain in place.

Cloudflare's shared proxy addresses are protected in the app, Go reporter and Python helper. This does not bypass request inspection. Remove wrongly attributed proxy IPs from every affected node's local agent:

```sh
sudo lwafd remove-ip 172.64.198.63
sudo lwafd remove-ip 172.64.198.149
```

If requests were attributed to the proxy, restore the verified visitor IP at Nginx using the [trusted Cloudflare example](../agent/deploy/cloudflare-real-ip.conf.example). Merge it into existing real-IP configuration, test with `nginx -t`, then reload Nginx manually. Do not trust forwarding headers from arbitrary direct connections. See [Cloudflare's visitor-IP guidance](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/).

Behind Cloudflare, enable the [Nginx reputation geo check](ip-reputation.md#traffic-forwarded-by-another-proxy) and keep `--nginx-geo-file=/var/lib/laravel-waf/reputation/nginx.geo` in cron/manual commands. Backend ipsets alone cannot match a forwarded visitor when the network peer is Cloudflare. No Ansible deployment is needed for these direct configuration updates.

The Cloudflare range snapshots in the components were checked on 2026-11-12 against the [IPv4](https://www.cloudflare.com/ips-v4/) and [IPv6](https://www.cloudflare.com/ips-v6/) lists. Keep them synchronized if the published ranges change.

## Compatibility

`LARAVEL_WAF_BSRBL_*` is the current setting family. Earlier `LARAVEL_WAF_BSABUSEIP_*` names remain supported; do not mix families. API-key formats are unchanged. The helper migrates earlier cache/cursor filenames when the BSRBL replacements are absent. New helper state uses `bsrbl-feed.json` and `bsrbl-reports.json` under the existing reputation directory.
