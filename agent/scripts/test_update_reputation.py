import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("reputation", Path(__file__).with_name("update-reputation.py"))
reputation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reputation)


class ReputationTest(unittest.TestCase):
    def test_parses_provider_formats_and_deduplicates(self):
        cases = {
            "tor": (
                b"ExitNode ABC\nPublished 2026-11-11 12:00:00\n"
                b"LastStatus 2026-11-11 12:00:00\n"
                b"ExitAddress 203.0.113.5 2026-11-11 12:00:00\n",
                {"203.0.113.5/32"},
            ),
            "spamhaus": (
                b'{"cidr":"2001:db8::/48","sblid":"SBL123"}\n'
                b'{"type":"metadata","copyright":"The Spamhaus Project"}\n',
                {"2001:db8::/48"},
            ),
            "netset": (
                b"# FireHOL\n203.0.113.7/24\n203.0.113.0/24 # duplicate\n198.51.100.9\n",
                {"203.0.113.0/24", "198.51.100.9/32"},
            ),
        }
        for format_name, (body, expected) in cases.items():
            with self.subTest(format_name=format_name):
                self.assertEqual(expected, {str(item) for item in reputation.parse_feed(body, format_name)})

    def test_rejects_empty_malformed_private_and_overly_broad_feeds(self):
        for body in (
            b"", b"# temporarily empty", b"<html>error</html>", b"8.8.8.8\ninvalid",
            b"0.0.0.0/0", b"::/0", b"2000::/3", b"127.0.0.1", b"10.0.0.0/8", b"fc00::/7",
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                reputation.parse_feed(body, "netset")

    def test_restore_batches_cidrs_and_expires_members_without_touching_dynamic_bans(self):
        entries = {
            reputation.network("203.0.113.0/24"): 1900,
            reputation.network("2001:db8::/48"): 2200,
            reputation.network("198.51.100.4"): 999,
        }
        body = reputation.restore_text(entries, [reputation.network("0.0.0.0/0")], 1000)
        self.assertIn("add lwaf_reputation_v4_next 203.0.113.0/24 timeout 900 -exist", body)
        self.assertIn("add lwaf_reputation_v6_next 2001:db8::/48 timeout 1200 -exist", body)
        self.assertNotIn("198.51.100.4", body)
        self.assertNotIn("laravel_waf_block", body)
        self.assertNotIn("add lwaf_rep_allow_v4_next 0.0.0.0/0", body)
        self.assertIn("add lwaf_rep_allow_v4_next 128.0.0.0/1", body)
        self.assertLess(body.rindex("\nadd "), body.index("\nswap "))
        self.assertNotIn("flush lwaf_reputation_v4\n", body)

    def test_download_failure_uses_cache_without_extending_its_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reputation, "download", return_value=b"203.0.113.4\n"), patch.object(reputation.time, "time", return_value=1000):
                initial, failed = reputation.collect(["firehol_level2"], directory, 7200)
            self.assertFalse(failed)
            with patch.object(reputation, "download", side_effect=OSError("offline")), patch.object(reputation.time, "time", return_value=2000):
                cached, failed = reputation.collect(["firehol_level2"], directory, 7200)
            self.assertTrue(failed)
            self.assertEqual(initial, cached)
            self.assertEqual(8200, cached[reputation.network("203.0.113.4")])
            with patch.object(reputation, "download", side_effect=OSError("offline")), patch.object(reputation.time, "time", return_value=8200):
                expired, failed = reputation.collect(["firehol_level2"], directory, 7200)
            self.assertTrue(failed)
            self.assertEqual({}, expired)

    def test_invalid_download_does_not_replace_good_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reputation, "download", return_value=b"203.0.113.4\n"):
                reputation.collect(["firehol_level2"], directory, 7200)
            path = Path(directory, "firehol_level2.json")
            before = path.read_bytes()
            with patch.object(reputation, "download", return_value=b"0.0.0.0/0\n"):
                entries, failed = reputation.collect(["firehol_level2"], directory, 7200)
            self.assertTrue(failed)
            self.assertTrue(entries)
            self.assertEqual(before, path.read_bytes())

    def test_malformed_json_records_and_cache_fail_without_clearing_other_feeds(self):
        with self.assertRaises(ValueError):
            reputation.parse_feed(b"[]\n", "spamhaus")
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "spamhaus_drop_v4.json").write_text(json.dumps({
                "fetched_at": 1000, "body": 123,
            }))
            def source(url):
                if "drop_v4" in url:
                    raise OSError("offline")
                return b"203.0.113.4\n"
            with patch.object(reputation, "download", side_effect=source), patch.object(reputation.time, "time", return_value=2000):
                entries, failed = reputation.collect(["spamhaus_drop_v4", "firehol_level2"], directory, 7200)
            self.assertTrue(failed)
            self.assertEqual({reputation.network("203.0.113.4"): 9200}, entries)

    def test_cache_retains_provider_copyright_and_dates(self):
        body = b'{"cidr":"2001:db8::/48"}\n{"type":"metadata","copyright":"The Spamhaus Project","timestamp":1794403604}\n'
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reputation, "download", return_value=body):
                reputation.collect(["spamhaus_drop_v6"], directory, 7200)
            cached = json.loads(Path(directory, "spamhaus_drop_v6.json").read_text())
            self.assertEqual(body.decode(), cached["body"])

    def test_dry_run_makes_no_files_or_firewall_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory, "absent")
            with patch.object(reputation, "download", return_value=b"203.0.113.4\n"), patch.object(reputation, "run") as command:
                self.assertEqual(0, reputation.main(["--dry-run", "--feeds=firehol_level2", f"--state-dir={state}"]))
            command.assert_not_called()
            self.assertFalse(state.exists())

    def test_restore_failure_does_not_attach_rules(self):
        with patch.object(reputation, "run", side_effect=RuntimeError("restore failed")) as command:
            with self.assertRaises(RuntimeError):
                reputation.enforce({}, [], "80,443", "ipset", "iptables", "ip6tables")
        self.assertEqual(1, command.call_count)
        self.assertEqual(["ipset", "restore"], command.call_args.args[0])

    def test_rule_installation_is_idempotent_and_replaces_only_our_old_ports(self):
        old_rule = '-A INPUT -p tcp -m multiport --dports 8080 -m set --match-set lwaf_reputation_v4 src -m comment --comment lwaf-reputation -j DROP\n'
        agent_rule = '-A INPUT -p tcp -m multiport --dports 8080 -m set --match-set laravel_waf_block_v4 src -j DROP\n'

        def execute(command, *_):
            if "-S" in command and command[0] == "iptables":
                return old_rule + agent_rule
            return ""

        with patch.object(reputation, "run", side_effect=execute) as command:
            reputation.enforce({}, [], "80,443", "ipset", "iptables", "ip6tables")
        calls = [call.args[0] for call in command.call_args_list]
        self.assertFalse(any("-I" in call for call in calls))
        deleted = [call for call in calls if "-D" in call]
        self.assertEqual(1, len(deleted))
        self.assertIn("lwaf_reputation_v4", deleted[0])
        self.assertNotIn("laravel_waf_block_v4", deleted[0])

    def test_nginx_allowlist_overrides_more_specific_blocks_and_mapped_ips(self):
        entries = {reputation.network("203.0.113.0/24"): 100, reputation.network("203.0.113.5"): 100}
        body = reputation.geo_text(entries, [reputation.network("203.0.112.0/23")])
        self.assertEqual(b"# Generated by lwaf-reputation; do not edit.\n", body)
        body = reputation.geo_text(entries, [reputation.network("::ffff:203.0.113.5")])
        prefixes = [ipaddress.ip_network(line.split()[0]) for line in body.decode().splitlines() if not line.startswith("#")]
        self.assertFalse(any(ipaddress.ip_address("203.0.113.5") in prefix for prefix in prefixes))
        self.assertTrue(any(ipaddress.ip_address("203.0.113.6") in prefix for prefix in prefixes))

    def test_nginx_invalid_configuration_restores_previous_file_without_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "reputation.geo")
            path.write_bytes(b"previous")
            with patch.object(reputation, "run", side_effect=RuntimeError("nginx test failed")) as command:
                with self.assertRaises(RuntimeError):
                    reputation.update_nginx(path, b"new", "nginx")
            self.assertEqual(b"previous", path.read_bytes())
            command.assert_called_once_with(["nginx", "-t"])


if __name__ == "__main__":
    unittest.main()
