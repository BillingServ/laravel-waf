#!/usr/bin/env python3
"""Refresh independent reputation ipsets alongside an existing LWAFD binary."""

import argparse
import contextlib
import fcntl
import gzip
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
import zlib


FEEDS = {
    "tor": ("https://check.torproject.org/exit-addresses", "tor"),
    "tor_ipv6": (
        "https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit"
        "&fields=running,flags,or_addresses,exit_addresses,exit_policy_v6_summary",
        "onionoo_ipv6",
    ),
    "blocklist_de": ("https://lists.blocklist.de/lists/all.txt", "netset"),
    "spamhaus_drop_v4": ("https://www.spamhaus.org/drop/drop_v4.json", "spamhaus"),
    "spamhaus_drop_v6": ("https://www.spamhaus.org/drop/drop_v6.json", "spamhaus"),
    "firehol_level2": (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "netset",
    ),
}
MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 250_000
SETS = {4: "lwaf_reputation_v4", 6: "lwaf_reputation_v6"}
ALLOW_SETS = {4: "lwaf_rep_allow_v4", 6: "lwaf_rep_allow_v6"}
LOCAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))
LOG = logging.getLogger("lwaf-reputation")


def network(value):
    """Canonicalize IPs and CIDRs without expanding networks into addresses."""
    result = ipaddress.ip_network(value, strict=False)
    if result.version == 6 and result.network_address.ipv4_mapped:
        if result.prefixlen < 96:
            raise ValueError("invalid IPv4-mapped network")
        return ipaddress.ip_network(
            f"{result.network_address.ipv4_mapped}/{result.prefixlen - 96}", strict=False
        )
    return result


def web_exit_policy(policy):
    if not isinstance(policy, dict) or set(policy) not in ({"accept"}, {"reject"}):
        raise ValueError("invalid IPv6 exit policy")
    action, ranges = next(iter(policy.items()))
    if not isinstance(ranges, list):
        raise ValueError("invalid IPv6 exit ports")
    matched = set()
    for value in ranges:
        if not isinstance(value, str):
            raise ValueError("invalid IPv6 exit port range")
        first, separator, last = value.partition("-")
        last = last if separator else first
        if not all(part.isascii() and part.isdigit() for part in (first, last)):
            raise ValueError("invalid IPv6 exit port range")
        lower, upper = int(first), int(last)
        if not 1 <= lower <= upper <= 65535:
            raise ValueError("invalid IPv6 exit port range")
        matched.update(port for port in (80, 443) if lower <= port <= upper)
    return bool(matched) if action == "accept" else len(matched) < 2


def onionoo_ipv6(body):
    document = json.loads(body)
    if not isinstance(document, dict) or not isinstance(document.get("relays"), list):
        raise ValueError("invalid Onionoo relay document")
    if document.get("relays_skipped") or document.get("relays_truncated"):
        raise ValueError("incomplete Onionoo relay document")
    addresses = set()
    for relay in document["relays"]:
        if not isinstance(relay, dict) or not isinstance(relay.get("flags"), list):
            raise ValueError("invalid Onionoo relay")
        if relay.get("running") is not True or "Exit" not in relay["flags"]:
            continue
        observed = relay.get("exit_addresses", [])
        advertised = relay.get("or_addresses", [])
        if not isinstance(observed, list) or not isinstance(advertised, list):
            raise ValueError("invalid Onionoo address lists")
        for value in observed:
            if not isinstance(value, str) or "%" in value:
                raise ValueError("invalid Onionoo exit address")
            address = ipaddress.ip_address(value)
            if address.version == 6 and not address.ipv4_mapped:
                addresses.add(str(address))
        policy = relay.get("exit_policy_v6_summary")
        if policy is None or not web_exit_policy(policy):
            continue
        # Onionoo's observed exit addresses are currently IPv4-only. Supplement
        # them with advertised IPv6 addresses of relays that permit web exits.
        # These are relay-associated addresses, not measured IPv6 exit addresses.
        for value in advertised:
            if not isinstance(value, str):
                raise ValueError("invalid Onionoo relay address")
            if not value.startswith("["):
                continue
            address, separator, port = value[1:].partition("]:")
            if not separator or not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("invalid Onionoo IPv6 relay address")
            address = ipaddress.IPv6Address(address)
            if address.ipv4_mapped or "%" in str(address):
                raise ValueError("invalid Onionoo IPv6 relay address")
            addresses.add(str(address))
    return "\n".join(sorted(addresses)).encode("utf-8")


def parse_feed(body, format_name):
    if len(body) > MAX_BYTES:
        raise ValueError("feed exceeds download limit")
    if format_name == "onionoo_ipv6":
        body = onionoo_ipv6(body)
        format_name = "netset"
    networks = set()
    for line in body.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if format_name == "tor":
            fields = line.split()
            if fields[0] in {"ExitNode", "Published", "LastStatus"}:
                continue
            if fields[0] != "ExitAddress" or len(fields) != 4:
                raise ValueError("invalid Tor exit record")
            value = fields[1]
        elif format_name == "spamhaus":
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("invalid Spamhaus record")
            if record.get("type") == "metadata":
                continue
            value = record["cidr"]
        elif format_name == "netset":
            value = line.partition("#")[0].strip()
        else:
            raise ValueError("unsupported feed format")
        prefix = network(value)
        minimum = 8 if prefix.version == 4 else 16
        if prefix.prefixlen < minimum:
            raise ValueError(f"refusing overly broad network: {prefix}")
        # Feeds describe public clients; never import local or multicast ranges.
        if any(
            address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified
            for address in (prefix.network_address, prefix.broadcast_address)
        ):
            raise ValueError(f"refusing non-public network: {prefix}")
        if any(prefix.version == local.version and prefix.overlaps(local) for local in LOCAL_NETWORKS):
            raise ValueError(f"refusing local network: {prefix}")
        networks.add(prefix)
        if len(networks) > MAX_ENTRIES:
            raise ValueError("feed exceeds entry limit")
    if not networks:
        raise ValueError("feed contains no networks")
    return networks


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def download(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "LWAF-Reputation/1.0", "Accept-Encoding": "gzip",
    })
    with urllib.request.build_opener(NoRedirects).open(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError(f"feed returned HTTP {response.status}")
        if response.headers.get("Content-Encoding", "").lower().strip() == "gzip":
            try:
                with gzip.GzipFile(fileobj=response) as stream:
                    return stream.read(MAX_BYTES + 1)
            except (EOFError, zlib.error) as error:
                raise ValueError("invalid compressed feed") from error
        return response.read(MAX_BYTES + 1)


def atomic_write(path, body, mode=0o600):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".reputation-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def collect(feeds, state_dir, max_age, dry_run=False):
    entries = {}
    failed = False
    for name in feeds:
        url, format_name = FEEDS[name]
        path = Path(state_dir) / f"{name}.json"
        now = time.time()
        try:
            body = download(url)
            prefixes = parse_feed(body, format_name)
            fetched_at = now
            if not dry_run:
                # Preserve original headers, provider dates, copyright, and terms.
                atomic_write(path, json.dumps({
                    "fetched_at": fetched_at, "body": body.decode("utf-8"),
                }).encode())
            ipv4 = sum(prefix.version == 4 for prefix in prefixes)
            LOG.info("feed=%s networks=%d ipv4=%d ipv6=%d refreshed", name, len(prefixes), ipv4, len(prefixes) - ipv4)
        except (OSError, ValueError, KeyError, TypeError) as error:
            failed = True
            LOG.error("feed=%s refresh failed: %s", name, error)
            try:
                with path.open("rb") as stream:
                    cached = json.loads(stream.read(2 * MAX_BYTES + 1))
                fetched_at = float(cached["fetched_at"])
                if not math.isfinite(fetched_at) or not 0 <= now - fetched_at < max_age:
                    raise ValueError("cached feed has expired or has an invalid timestamp")
                if not isinstance(cached["body"], str):
                    raise ValueError("invalid cached feed body")
                prefixes = parse_feed(cached["body"].encode("utf-8"), format_name)
                LOG.warning("feed=%s using cached data", name)
            except (OSError, ValueError, KeyError, TypeError) as cache_error:
                LOG.error("feed=%s unavailable: %s", name, cache_error)
                continue
        expiry = fetched_at + max_age
        for prefix in prefixes:
            entries[prefix] = max(expiry, entries.get(prefix, 0))
    return entries, failed


def run(command, input_text=None):
    result = subprocess.run(
        command, input=input_text, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)}: {result.stderr.strip()}")
    return result.stdout


def restore_text(entries, allowed, now):
    lines = []
    for version, family in ((4, "inet"), (6, "inet6")):
        for name, timed in ((SETS[version], True), (ALLOW_SETS[version], False)):
            timeout = " timeout 604800" if timed else ""
            for target in (name, name + "_next"):
                lines.append(
                    f"create {target} hash:net family {family}{timeout} "
                    "hashsize 65536 maxelem 1000000 -exist"
                )
            lines.append(f"flush {name}_next")
    for prefix, expiry in sorted(entries.items(), key=lambda item: str(item[0])):
        ttl = min(604800, int(expiry - now))
        if ttl > 0:
            lines.append(f"add {SETS[prefix.version]}_next {prefix} timeout {ttl} -exist")
    for prefix in allowed:
        if prefix.prefixlen == 0:
            # ipset hash:net rejects /0. Two /1 ranges have the same meaning.
            ranges = prefix.subnets(prefixlen_diff=1)
        else:
            ranges = [prefix]
        lines.extend(f"add {ALLOW_SETS[prefix.version]}_next {item} -exist" for item in ranges)
    # Populate every staging set before swapping any live set. Refreshes never
    # flush LWAFD's dynamic bans or expose a partially imported live feed.
    for name in (*ALLOW_SETS.values(), *SETS.values()):
        lines.extend((f"swap {name}_next {name}", f"destroy {name}_next"))
    return "\n".join(lines) + "\n"


def enforce(entries, allowed, ports, ipset, iptables, ip6tables):
    run([ipset, "restore"], restore_text(entries, allowed, time.time()))
    for version, executable in ((4, iptables), (6, ip6tables)):
        rule = [
            "!", "-i", "lo", "-p", "tcp", "-m", "multiport", "--dports", ports,
            "-m", "set", "--match-set", SETS[version], "src",
            "-m", "set", "!", "--match-set", ALLOW_SETS[version], "src", "-j", "DROP",
        ]
        # Only this helper's comment identifies rules that may need replacing
        # when ports change; rules belonging to the existing agent are untouched.
        rule[-2:-2] = ["-m", "comment", "--comment", "lwaf-reputation"]
        try:
            run([executable, "-w", "5", "-C", "INPUT", *rule])
        except RuntimeError:
            run([executable, "-w", "5", "-I", "INPUT", "1", *rule])
        # Install the new policy before removing an older port configuration.
        existing = run([executable, "-w", "5", "-S", "INPUT"])
        for line in existing.splitlines():
            fields = shlex.split(line)
            if fields[:2] != ["-A", "INPUT"] or "--comment" not in fields or "--dports" not in fields:
                continue
            if fields[fields.index("--comment") + 1] != "lwaf-reputation":
                continue
            if "--match-set" not in fields or fields[fields.index("--match-set") + 1] != SETS[version]:
                continue
            if fields[fields.index("--dports") + 1] != ports:
                run([executable, "-w", "5", "-D", *fields[1:]])


def geo_text(entries, allowed):
    """Make an Nginx geo include with allowlists taking precedence over blocks."""
    remaining = []
    for version in (4, 6):
        prefixes = ipaddress.collapse_addresses(p for p in entries if p.version == version)
        for prefix in prefixes:
            chunks = [prefix]
            for exception in allowed:
                if exception.version != version:
                    continue
                updated = []
                for chunk in chunks:
                    if not chunk.overlaps(exception):
                        updated.append(chunk)
                    elif exception.subnet_of(chunk):
                        updated.extend(chunk.address_exclude(exception))
                chunks = updated
            remaining.extend(chunks)
    return (
        "# Generated by lwaf-reputation; do not edit.\n"
        + "".join(f"{prefix} 1;\n" for prefix in remaining)
    ).encode()


def update_nginx(path, body, executable):
    path = Path(path)
    previous = path.read_bytes() if path.exists() else None
    if previous == body:
        return
    atomic_write(path, body, 0o644)
    try:
        run([executable, "-t"])
        run([executable, "-s", "reload"])
    except (RuntimeError, OSError, subprocess.SubprocessError):
        if previous is None:
            path.unlink()
        else:
            atomic_write(path, previous, 0o644)
        raise


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feeds", default=",".join(FEEDS))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/laravel-waf/reputation"))
    parser.add_argument("--max-age", type=int, default=172800, help="cached feed lifetime in seconds")
    parser.add_argument("--allow-ips", default="", help="comma-separated IPs/CIDRs exempt from reputation")
    parser.add_argument("--ports", default="80,443")
    parser.add_argument("--ipset", default="/usr/sbin/ipset")
    parser.add_argument("--iptables", default="/usr/sbin/iptables")
    parser.add_argument("--ip6tables", default="/usr/sbin/ip6tables")
    parser.add_argument("--nginx-geo-file", type=Path, help="optional Nginx geo include; tests and reloads Nginx")
    parser.add_argument("--nginx", default="/usr/sbin/nginx")
    parser.add_argument("--dry-run", action="store_true", help="fetch and validate without writing files or firewall rules")
    args = parser.parse_args(argv)
    args.feeds = list(dict.fromkeys(item.strip() for item in args.feeds.split(",") if item.strip()))
    if not args.feeds or any(name not in FEEDS for name in args.feeds):
        parser.error("--feeds must select known feeds: " + ",".join(FEEDS))
    # Existing --feeds=tor deployments receive IPv6 coverage after updating.
    if "tor" in args.feeds and "tor_ipv6" not in args.feeds:
        args.feeds.insert(args.feeds.index("tor") + 1, "tor_ipv6")
    if not args.state_dir.is_absolute() or not 7200 <= args.max_age <= 604800:
        parser.error("--state-dir must be absolute; --max-age must be between 7200 and 604800 seconds")
    ports = args.ports.split(",")
    if len(ports) > 15 or any(not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535 for port in ports):
        parser.error("--ports must contain between 1 and 15 TCP ports")
    args.ports = ",".join(str(int(port)) for port in ports)
    try:
        args.allowed = [network(item.strip()) for item in args.allow_ips.split(",") if item.strip()]
    except ValueError as error:
        parser.error(str(error))
    if args.nginx_geo_file and not args.nginx_geo_file.is_absolute():
        parser.error("--nginx-geo-file must be absolute")
    return args


def update(args):
    entries, failed = collect(args.feeds, args.state_dir, args.max_age, args.dry_run)
    if args.dry_run:
        LOG.info("dry-run networks=%d; no files or firewall rules changed", len(entries))
        return int(failed)
    # Also rebuild empty results: kernel timeouts and Nginx must release expired
    # data, even when every provider is unavailable.
    enforce(entries, args.allowed, args.ports, args.ipset, args.iptables, args.ip6tables)
    if args.nginx_geo_file:
        update_nginx(args.nginx_geo_file, geo_text(entries, args.allowed), args.nginx)
    ipv4 = sum(prefix.version == 4 for prefix in entries)
    LOG.info("active reputation networks=%d ipv4=%d ipv6=%d", len(entries), ipv4, len(entries) - ipv4)
    return int(failed)


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = arguments(argv)
    if args.dry_run:
        return update(args)
    if os.geteuid() != 0:
        raise RuntimeError("firewall updates require root; use --dry-run to validate feeds")
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    with (args.state_dir / ".update.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return update(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        LOG.error("reputation update failed: %s", error)
        sys.exit(1)
