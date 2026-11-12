# BSRBL reporting and shared blocks

The reputation helper connects the WAF to BSRBL at `https://rbl.bserv.uk`:

| Request | Permission | Purpose |
| --- | --- | --- |
| `GET /api/v1/feed` | `read` | Pull active IPv4 and IPv6 blocks into the reputation firewall sets |
| `POST /api/v1/reports` | `report` | Submit active bans from the existing agent ledger |

Both requests use `Authorization: Bearer YOUR_KEY`. The helper requires HTTPS, verifies certificates, refuses redirects, and keeps keys out of URLs, logs and cache files. BSRBL block reasons are public on its lookup page; reporting sends the IP, reason and expiry, without request or attack logs.

## Create a key on the BSRBL server

Run from the BSRBL application directory as its hosting/PHP account:

```sh
php bin/console key:create --name=server-1 --scopes=read,report --days=0
```

`--days=0` creates a key that stays valid until revoked. Use a separate key for each WAF server. The key is shown once. A key created with only `read` permission can pull the feed but cannot report bans.

## Configure each WAF server

Deploy the updated `agent/scripts/update-reputation.py` from this package. Existing Go binaries do not need rebuilding or restarting. Add to each Laravel application's `.env`:

```dotenv
LARAVEL_WAF_BSRBL_URL=https://rbl.bserv.uk
LARAVEL_WAF_BSRBL_API_KEY=the-key-for-this-server
LARAVEL_WAF_BSRBL_REPORT_ENABLED=true
```

Use the base URL above, without `/api/v1/feed` or the private admin path. The helper appends the API routes. With a URL and key configured it always pulls the feed. Reporting is opt-in; set `LARAVEL_WAF_BSRBL_REPORT_ENABLED=false` to keep downloads and stop submissions. Remove the BSRBL settings to disable the integration entirely.

For Composer installations at `vendor/billingserv/laravel-waf`, the helper automatically finds the application's `.env`, including deployments using a stable `current` symlink. For other layouts add `--env-file=/absolute/path/to/.env` to the helper command. Process environment values override `.env` values. Parsing is literal, without shell execution or variable interpolation; Laravel's config cache does not affect it.

The default agent ledger is `/var/lib/laravel-waf/blocks.json`. If yours differs:

```dotenv
LARAVEL_WAF_BSRBL_STATE_FILE=/absolute/path/to/blocks.json
```

## Run and schedule

Replace `/app` with your actual Laravel application path:

```sh
# Download and validate feeds; no reports, file writes, or firewall changes.
sudo /usr/bin/python3 /app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py --dry-run

# Apply shared/public blocks and report new active local bans now.
sudo /usr/bin/python3 /app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py
```

Existing hourly reputation cron jobs automatically include BSRBL after the helper and `.env` are updated. If the host has no job yet, add these entries to root's crontab, adjusting the path:

```cron
17 * * * * /usr/bin/python3 /app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
@reboot /bin/sleep 30 && /usr/bin/python3 /app/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py >> /var/log/lwaf-reputation.log 2>&1
```

Run one reputation job per ingress host. Keep any existing `--allow-ips`, `--ports`, or `--nginx-geo-file` options when updating its command. The helper uses the existing public feeds alongside BSRBL. It blocks the configured TCP ports, 80/443 by default, independently of Laravel's log/challenge mode. It does not add downloaded addresses to the agent's local ledger, so shared entries do not create a reporting loop.

## Behaviour and timing

The helper pulls BSRBL, refreshes the firewall and optional Nginx include, then reports active local bans. A report failure does not prevent the firewall refresh. Up to 100 reports are sent per run within a 30-second reporting budget; failed submissions retry while the local ban remains active. Successfully acknowledged unchanged bans are deduplicated.

Polling happens on the helper's schedule. A local ban must still be active when the job reads the agent ledger; short bans can be missed. Another server receives a newly reported block on its next hourly download, potentially roughly two hours after the original ban. This does not install an immediate hook into `lwafs add-ip`. For faster reporting, this same helper can optionally run more frequently with `--report-only`; that mode shares the lock/cursor and does not pull feeds or alter firewall rules.

Finite bans retain their original expiry, capped to 30 days for unusually long reports. Permanent manual BSRBL entries are refreshed with the feed. A valid empty feed clears this source. Failed or invalid downloads retain a usable private cache for at most `--max-age` (48 hours by default), without extending an individual ban beyond its expiry. Nginx includes update on the helper's schedule; kernel ipset timeouts expire independently.

Administrator exclusions prevent automatic reports re-adding an address to BSRBL. They do not override local agent blocks or other public feeds. Use the existing reputation allowlist when an address must bypass reputation blocking on a host.

## Logs and compatibility

Successful downloads log `feed=bsrbl` with IPv4/IPv6 counts. Reports log `BSRBL acknowledged=... pending=...`. State files are `bsrbl-feed.json` and `bsrbl-reports.json` in the existing reputation state directory, normally `/var/lib/laravel-waf/reputation`, with owner-only file permissions.

Earlier `LARAVEL_WAF_BSABUSEIP_*` settings are still accepted. If any `LARAVEL_WAF_BSRBL_*` setting is present, the BSRBL setting family is selected as a whole; configure all three values together instead of mixing old and new names. Earlier `bsabuseip-*.json` cache/cursor files are read when their BSRBL replacement is absent. New writes use BSRBL filenames, preserving deduplication and usable cached blocks during upgrades.
