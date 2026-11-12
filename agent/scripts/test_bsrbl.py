import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bsrbl_reputation", Path(__file__).with_name("update-reputation.py"))
rep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rep)
TOKEN = "bsai_" + "a" * 16 + "_" + "b" * 64
PREFIX = "LARAVEL_WAF_BSRBL_"


class BSRBLIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = rep.arguments(["--state-dir", str(self.root)])
        self.config = {"url": "https://abuse.example", "api_key": TOKEN, "report_enabled": True, "state_file": self.root / "blocks.json"}
        environment = patch.dict(os.environ, {PREFIX + "URL": "", PREFIX + "API_KEY": "", PREFIX + "REPORT_ENABLED": "false"})
        environment.start()
        self.addCleanup(environment.stop)
        self.now = int(time.time())

    def document(self, records=None):
        return {"version": 1, "blocks": records if records is not None else [{"ip": "154.9.244.17", "expires_at": None}]}

    def ledger(self, records=None):
        self.config["state_file"].write_text(json.dumps({"version": 1, "blocks": records if records is not None else [
            {"ip": "154.9.244.17", "reason": "manual", "expires_at": self.now + 3600},
            {"ip": "185.220.101.23", "reason": "header_line_break", "expires_at": self.now + 3600},
        ]}))

    def test_disabled_by_default_and_read_only_settings(self):
        self.assertIsNone(rep.report_settings(self.args))
        with patch.dict(os.environ, {PREFIX + "URL": self.config["url"], PREFIX + "API_KEY": TOKEN}):
            config = rep.report_settings(self.args)
        self.assertFalse(config["report_enabled"])
        self.assertEqual(self.config["url"], config["url"])

    def test_dotenv_literal_parsing_and_process_overrides(self):
        env_file = self.root / ".env"
        env_file.write_text(f"UNRELATED=$(touch bad)\n{PREFIX}URL='https://abuse.example' # note\n{PREFIX}API_KEY={TOKEN}\n{PREFIX}REPORT_ENABLED=true\n")
        self.args.env_file = env_file
        with patch.dict(os.environ, {}, clear=True):
            config = rep.report_settings(self.args)
        self.assertTrue(config["report_enabled"])
        self.assertFalse((self.root / "bad").exists())
        self.assertEqual("/var/lib/laravel-waf/blocks.json", str(config["state_file"]))

    def test_rejects_insecure_urls_and_missing_credentials(self):
        for url in ["http://abuse.example", "https://user:pass@abuse.example", "https://abuse.example/api", "https://abuse.example?key=x", "https://abuse.example#x"]:
            with self.subTest(url=url), patch.dict(os.environ, {PREFIX + "URL": url, PREFIX + "API_KEY": TOKEN}), self.assertRaises(ValueError):
                rep.report_settings(self.args)
        with patch.dict(os.environ, {PREFIX + "REPORT_ENABLED": "true"}), self.assertRaises(ValueError):
            rep.report_settings(self.args)

    def test_legacy_configuration_and_new_prefix_precedence(self):
        legacy = "LARAVEL_WAF_BSABUSEIP_"
        old = {legacy + "URL": self.config["url"], legacy + "API_KEY": TOKEN,
               legacy + "REPORT_ENABLED": "true"}
        with patch.dict(os.environ, old, clear=True):
            self.assertTrue(rep.report_settings(self.args)["report_enabled"])
        # New settings select a complete family; never reuse another URL's key.
        with patch.dict(os.environ, {**old, PREFIX + "URL": "https://rbl.bserv.uk"}, clear=True):
            with self.assertRaises(ValueError):
                rep.report_settings(self.args)
        with patch.dict(os.environ, {**old, PREFIX + "REPORT_ENABLED": "false"}, clear=True):
            self.assertIsNone(rep.report_settings(self.args))

    def test_process_environment_overrides_dotenv_and_composer_path_is_stable(self):
        self.args.env_file = self.root / ".env"
        self.args.env_file.write_text(
            f"{PREFIX}URL=https://old.example\n{PREFIX}API_KEY={TOKEN}\n{PREFIX}REPORT_ENABLED=false\n"
        )
        with patch.dict(os.environ, {PREFIX + "URL": "https://rbl.bserv.uk", PREFIX + "REPORT_ENABLED": "true"}, clear=True):
            config = rep.report_settings(self.args)
        self.assertEqual("https://rbl.bserv.uk", config["url"])
        self.assertTrue(config["report_enabled"])
        path = "/var/www/app/current/vendor/billingserv/laravel-waf/agent/scripts/update-reputation.py"
        self.assertEqual(Path("/var/www/app/current/.env"), rep.application_env_file(path))
        self.assertIsNone(rep.application_env_file("/opt/laravel-waf/agent/scripts/update-reputation.py"))

    def test_legacy_cache_is_used_but_cannot_override_a_new_empty_feed(self):
        legacy = self.root / "bsabuseip-feed.json"
        legacy.write_text(json.dumps({
            "url": self.config["url"], "fetched_at": self.now, "document": self.document(),
        }))
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", side_effect=ValueError):
            records, failed = rep.collect_registry(self.args)
        self.assertTrue(failed)
        self.assertIn(rep.network("154.9.244.17"), records)
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value=self.document([])):
            self.assertEqual(({}, False), rep.collect_registry(self.args))
        self.assertTrue((self.root / "bsrbl-feed.json").exists())
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", side_effect=ValueError):
            self.assertEqual(({}, True), rep.collect_registry(self.args))

    def test_legacy_report_cursor_prevents_duplicates_and_new_writes_use_bsrbl(self):
        self.ledger()
        pending, cursor = rep.report_candidates(self.config, self.args, self.now)
        cursor["sent"] = {r["ip"]: {"fingerprint": r["fingerprint"], "expires_at": r["expires_at"]} for r in pending}
        (self.root / "bsabuseip-reports.json").write_text(json.dumps(cursor))
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as send:
            self.assertFalse(rep.report_blocks(self.args))
            send.assert_not_called()
        records = json.loads(self.config["state_file"].read_text())["blocks"]
        records[0]["expires_at"] += 60
        self.ledger(records)
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as send:
            self.assertFalse(rep.report_blocks(self.args))
            self.assertEqual(1, send.call_count)
        self.assertTrue((self.root / "bsrbl-reports.json").exists())

    def test_truncated_responses_and_http_errors_hide_secrets(self):
        errors = [
            rep.http.client.IncompleteRead(TOKEN.encode(), 1000),
            rep.urllib.error.HTTPError(self.config["url"], 403, "forbidden", {}, io.BytesIO(TOKEN.encode())),
        ]
        for error in errors:
            with patch.object(rep.urllib.request, "build_opener") as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaisesRegex(ValueError, "^BSRBL request failed$") as caught:
                    rep.registry_request(self.config, "/api/v1/feed")
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_default_run_with_reporting_enabled_downloads_without_reporting_or_editing_agent_ledger(self):
        self.args.env_file = self.root / ".env"
        self.args.env_file.write_text(
            f"{PREFIX}URL=https://rbl.bserv.uk\n{PREFIX}API_KEY={TOKEN}\n"
            f"{PREFIX}REPORT_ENABLED=true\n{PREFIX}STATE_FILE={self.config['state_file']}\n"
        )
        self.ledger([{"ip": "185.220.101.23", "reason": "manual", "expires_at": self.now + 3600}])
        original = self.config["state_file"].read_bytes()
        order = []
        def response(config, endpoint, payload=None, timeout=15):
            self.assertEqual("https://rbl.bserv.uk", config["url"])
            self.assertEqual(TOKEN, config["api_key"])
            order.append(endpoint)
            if endpoint == "/api/v1/feed":
                return self.document([
                    {"ip": "154.9.244.17", "expires_at": None},
                    {"ip": "2001:4860:4860::8888", "expires_at": self.now + 600},
                ])
            self.fail("Default download run attempted to submit a report")
        with patch.dict(os.environ, {}, clear=True), patch.object(rep, "collect", return_value=({}, False)), patch.object(rep, "registry_request", side_effect=response), patch.object(rep, "enforce", side_effect=lambda *args: order.append("firewall")) as enforce:
            self.assertEqual(0, rep.update(self.args))
        self.assertEqual(["/api/v1/feed", "firewall"], order)
        self.assertEqual({rep.network("154.9.244.17"), rep.network("2001:4860:4860::8888")}, set(enforce.call_args.args[0]))
        self.assertEqual(original, self.config["state_file"].read_bytes())
        self.assertNotIn(TOKEN, (self.root / "bsrbl-feed.json").read_text())
        self.assertFalse((self.root / "bsrbl-reports.json").exists())

    def test_dry_run_does_not_write_a_registry_cache(self):
        self.args.dry_run = True
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value=self.document()):
            records, failed = rep.collect_registry(self.args)
        self.assertTrue(records)
        self.assertFalse(failed)
        self.assertFalse((self.root / "bsrbl-feed.json").exists())

    def test_bearer_transport_and_no_redirects(self):
        response = io.BytesIO(json.dumps(self.document()).encode())
        response.status = 200
        with patch.object(rep.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(self.document(), rep.registry_request(self.config, "/api/v1/feed"))
        self.assertIs(opener.call_args.args[0], rep.NoRedirects)
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual("Bearer " + TOKEN, request.get_header("Authorization"))
        self.assertNotIn(TOKEN, request.full_url)
        self.assertEqual("LWAF-BSRBL/1.0", request.get_header("User-agent"))
        self.assertEqual("GET", request.get_method())

    def test_valid_empty_feed_and_original_expiry(self):
        self.assertEqual({}, rep.parse_registry(self.document([]), self.now))
        document = self.document([
            {"ip": "::ffff:154.9.244.17", "expires_at": self.now + 60},
            {"ip": "2001:4860:4860::8888", "expires_at": self.now - 1},
        ])
        self.assertEqual({rep.network("154.9.244.17"): self.now + 60}, rep.parse_registry(document, self.now))

    def test_rejects_corrupt_private_and_broad_feed_records(self):
        documents = [[], {}, {"version": True, "blocks": []}, self.document([{"ip": "8.8.8.8"}])]
        for value in ["127.0.0.1", "10.1.1.1", "224.0.0.1", "::ffff:10.0.0.1", "8.8.8.8/24", "2001:4860:4860::8888%eth0"]:
            documents.append(self.document([{"ip": value, "expires_at": None}]))
        documents.append(self.document([{"ip": "8.8.8.8", "expires_at": True}]))
        for document in documents:
            with self.subTest(document=document), self.assertRaises((ValueError, TypeError)):
                rep.parse_registry(document, self.now)

    def test_private_cache_fallback_and_expiry_cap(self):
        document = self.document([{"ip": "154.9.244.17", "expires_at": self.now + 60}])
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value=document):
            entries, failed = rep.collect_registry(self.args)
        self.assertFalse(failed)
        self.assertEqual(self.now + 60, entries[rep.network("154.9.244.17")])
        path = self.root / "bsrbl-feed.json"
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertNotIn(TOKEN, path.read_text())
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", side_effect=ValueError):
            cached, failed = rep.collect_registry(self.args)
        self.assertTrue(failed)
        self.assertEqual(entries, cached)
        data = json.loads(path.read_text())
        data["fetched_at"] = self.now - self.args.max_age - 1
        path.write_text(json.dumps(data))
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", side_effect=ValueError):
            self.assertEqual(({}, True), rep.collect_registry(self.args))

    def test_valid_empty_feed_replaces_cache_and_bad_feed_preserves_cache(self):
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value=self.document()):
            rep.collect_registry(self.args)
        path = self.root / "bsrbl-feed.json"
        original = path.read_bytes()
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value={"broken": 1}):
            entries, failed = rep.collect_registry(self.args)
        self.assertTrue(entries)
        self.assertTrue(failed)
        self.assertEqual(original, path.read_bytes())
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", return_value=self.document([])):
            self.assertEqual(({}, False), rep.collect_registry(self.args))

    def test_cache_cannot_follow_a_different_registry(self):
        path = self.root / "bsrbl-feed.json"
        path.write_text(json.dumps({"url": "https://other.example", "fetched_at": self.now, "document": self.document()}))
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "registry_request", side_effect=ValueError):
            self.assertEqual(({}, True), rep.collect_registry(self.args))

    def test_candidate_dedup_expired_and_allowlist(self):
        self.ledger([
            {"ip": "154.9.244.17", "reason": "manual", "expires_at": self.now + 60},
            {"ip": "185.220.101.23", "reason": "manual", "expires_at": self.now - 1},
            {"ip": "10.0.0.1", "reason": "manual", "expires_at": self.now + 60},
            {"ip": "8.8.8.8", "reason": "manual", "expires_at": self.now + 60},
        ])
        self.args.allowed = [rep.network("8.8.8.8")]
        pending, cursor = rep.report_candidates(self.config, self.args, self.now)
        self.assertEqual(["154.9.244.17"], [r["ip"] for r in pending])
        record = pending[0]
        cursor["sent"][record["ip"]] = {"expires_at": record["expires_at"], "fingerprint": record["fingerprint"]}
        (self.root / "bsrbl-reports.json").write_text(json.dumps(cursor))
        self.assertEqual([], rep.report_candidates(self.config, self.args, self.now)[0])

    def test_reports_without_logs_and_only_acknowledges_success(self):
        self.ledger()
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as submit:
            self.assertFalse(rep.report_blocks(self.args))
        self.assertEqual(2, submit.call_count)
        record = submit.call_args.args[1]
        self.assertEqual(self.now + 3600, record["expires_at"])
        self.assertIn("reason", record)
        self.assertNotIn("logs", record)
        self.assertNotIn(TOKEN, (self.root / "bsrbl-reports.json").read_text())
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as submit:
            self.assertFalse(rep.report_blocks(self.args))
            submit.assert_not_called()

    def test_dry_run_and_failure_do_not_acknowledge(self):
        self.ledger()
        self.args.dry_run = True
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as submit:
            self.assertFalse(rep.report_blocks(self.args))
            submit.assert_not_called()
        self.assertFalse((self.root / "bsrbl-reports.json").exists())
        self.args.dry_run = False
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report", side_effect=ValueError(TOKEN)), self.assertLogs(rep.LOG, "ERROR") as logs:
            self.assertTrue(rep.report_blocks(self.args))
        self.assertNotIn(TOKEN, str(logs.output))
        self.assertFalse((self.root / "bsrbl-reports.json").exists())

    def test_cloudflare_proxies_are_not_reported_or_imported_from_bsrbl(self):
        proxies = ["172.64.198.63", "172.64.198.149", "::ffff:172.64.198.63", "2606:4700::1234"]
        for value in proxies:
            self.ledger([{"ip": value, "reason": "sig:env-vcs-probe", "expires_at": self.now + 3600}])
            self.assertEqual([], rep.report_candidates(self.config, self.args, self.now)[0])
            document = self.document([{"ip": value, "expires_at": None}, {"ip": "38.244.29.125", "expires_at": None}])
            self.assertEqual({rep.network("38.244.29.125"): None}, rep.parse_registry(document, self.now))
        for value in ["38.244.29.125", "172.63.255.255", "172.72.0.1", "2001:4860:4860::8888"]:
            self.assertFalse(rep.protected_proxy(ipaddress.ip_address(value)))

    def test_report_payload_and_registry_acknowledgement(self):
        record = {"ip": "154.9.244.17", "reason": "manual", "expires_at": self.now + 3600}
        for result in ["accepted", "unchanged", "protected"]:
            with patch.object(rep, "registry_request", return_value={"status": "ok", "ip": record["ip"], "result": result}) as request:
                rep.submit_report(self.config, record, 10)
                payload = json.loads(request.call_args.args[2])
                self.assertEqual({"ip": record["ip"], "reason": record["reason"], "expires_at": None}, payload)
        with patch.object(rep, "registry_request", return_value={"status": "ok"}), self.assertRaises(ValueError):
            rep.submit_report(self.config, record, 10)

    def test_default_and_explicit_downloads_never_submit_reports(self):
        for mode in [[], ["--download-only"]]:
            for dry_run in [False, True]:
                with self.subTest(mode=mode, dry_run=dry_run):
                    args = rep.arguments(["--state-dir", str(self.root)] + mode)
                    args.dry_run = dry_run
                    with patch.object(rep, "collect", return_value=({}, False)), patch.object(rep, "collect_registry", return_value=({rep.network("38.244.29.125"): self.now + 3600}, False)), patch.object(rep, "enforce") as enforce, patch.object(rep, "report_blocks") as report:
                        self.assertEqual(0, rep.update(args))
                        report.assert_not_called()
                        if dry_run:
                            enforce.assert_not_called()
                        else:
                            enforce.assert_called_once()

    def test_report_only_uses_its_own_lock_while_refresh_runs(self):
        self.ledger()
        with (self.root / ".update.lock").open("a") as refresh:
            rep.fcntl.flock(refresh, rep.fcntl.LOCK_EX | rep.fcntl.LOCK_NB)
            with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as report, patch.object(rep, "collect") as collect, patch.object(rep, "collect_registry") as registry, patch.object(rep, "enforce") as enforce:
                self.assertEqual(0, rep.main(["--state-dir", str(self.root), "--report-only"]))
                self.assertEqual(2, report.call_count)
                collect.assert_not_called()
                registry.assert_not_called()
                enforce.assert_not_called()
        self.assertEqual(0o600, (self.root / ".report.lock").stat().st_mode & 0o777)

    def test_partial_backfill_requests_a_retry_and_then_drains(self):
        self.ledger()
        with patch.object(rep, "report_settings", return_value=self.config), patch.object(rep, "submit_report") as report, patch.object(rep, "REPORT_MAX_PER_RUN", 1):
            self.assertTrue(rep.report_blocks(self.args))
            self.assertFalse(rep.report_blocks(self.args))
            self.assertEqual(2, report.call_count)

    def test_download_and_report_only_are_mutually_exclusive(self):
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            rep.arguments(["--download-only", "--report-only"])

    def test_default_refresh_merges_public_and_private_feeds_and_preserves_failures(self):
        public = {rep.network("8.8.8.8"): self.now + 3600}
        shared = {rep.network("154.9.244.17"): self.now + 3600}
        for public_failed, shared_failed in [(False, False), (True, False), (False, True)]:
            with self.subTest(public_failed=public_failed, shared_failed=shared_failed):
                with patch.object(rep, "collect", return_value=(dict(public), public_failed)), patch.object(rep, "collect_registry", return_value=(shared, shared_failed)), patch.object(rep, "enforce") as enforce, patch.object(rep, "report_blocks") as report:
                    self.assertEqual(int(public_failed or shared_failed), rep.update(self.args))
                    report.assert_not_called()
                    self.assertEqual(set(public) | set(shared), set(enforce.call_args.args[0]))
        self.assertEqual("https://lists.blocklist.de/lists/all.txt", rep.FEEDS["blocklist_de"][0])


if __name__ == "__main__":
    unittest.main()
