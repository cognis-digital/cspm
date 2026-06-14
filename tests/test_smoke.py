"""Smoke tests for CSPM. Offline, standard library only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cspm import TOOL_NAME, TOOL_VERSION, scan, summarize  # noqa: E402
from cspm.cli import main, _render_html  # noqa: E402
from cspm.core import load_config  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(__file__), "..", "demos", "01-basic", "account_export.json"
)


class TestCore(unittest.TestCase):
    def setUp(self):
        self.config = load_config(DEMO)
        self.findings = scan(self.config)

    def test_finds_issues(self):
        self.assertTrue(self.findings, "expected findings from the demo export")

    def test_sorted_by_severity_desc(self):
        from cspm.core import SEVERITY_ORDER
        ranks = [SEVERITY_ORDER[f.severity] for f in self.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_detects_public_rw_bucket(self):
        ids = {(f.check_id, f.resource) for f in self.findings}
        self.assertIn(("S3_PUBLIC", "customer-backups"), ids)
        crit = [f for f in self.findings
                if f.resource == "customer-backups" and f.check_id == "S3_PUBLIC"]
        self.assertEqual(crit[0].severity, "CRITICAL")

    def test_detects_open_db_ports(self):
        ids = {f.check_id for f in self.findings}
        self.assertIn("SG_OPEN_SENSITIVE", ids)
        sensitive = [f for f in self.findings if f.check_id == "SG_OPEN_SENSITIVE"]
        self.assertTrue(all(f.severity == "CRITICAL" for f in sensitive))

    def test_detects_open_all(self):
        self.assertIn("SG_OPEN_ALL", {f.check_id for f in self.findings})

    def test_detects_admin_without_mfa(self):
        admin = [f for f in self.findings if f.check_id == "IAM_ADMIN_NO_MFA"]
        self.assertEqual(len(admin), 1)
        self.assertEqual(admin[0].resource, "alice-admin")

    def test_detects_wildcard_policy(self):
        self.assertIn("IAM_WILDCARD_POLICY", {f.check_id for f in self.findings})

    def test_detects_stale_and_multi_keys(self):
        ids = {f.check_id for f in self.findings}
        self.assertIn("IAM_STALE_KEY", ids)
        self.assertIn("IAM_MULTI_KEYS", ids)

    def test_summary_counts_match(self):
        summary = summarize(self.findings)
        self.assertEqual(summary["total"], len(self.findings))
        self.assertEqual(sum(summary["by_severity"].values()), len(self.findings))
        self.assertEqual(summary["worst"], "CRITICAL")


class TestEdgeCases(unittest.TestCase):
    def test_empty_config_no_findings(self):
        self.assertEqual(scan({}), [])
        self.assertEqual(summarize([])["total"], 0)

    def test_clean_resources(self):
        cfg = {
            "buckets": [{
                "name": "clean", "acl": "private", "public_access_block": True,
                "encryption": "AES256", "versioning": True, "logging": True,
            }],
            "security_groups": [{
                "id": "sg-ok",
                "ingress": [{"protocol": "tcp", "port": 443, "cidr": "10.0.0.0/8"}],
            }],
            "iam_users": [{
                "name": "ok", "console_access": True, "mfa_enabled": True,
                "access_keys": [{"id": "k", "active": True, "age_days": 5}],
            }],
        }
        self.assertEqual(scan(cfg), [])


class TestCLI(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_scan_exit_nonzero_on_findings(self):
        self.assertEqual(main(["scan", DEMO, "--format", "json"]), 1)

    def test_scan_json_is_valid(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["scan", DEMO, "--format", "json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], TOOL_NAME)
        self.assertEqual(data["version"], TOOL_VERSION)
        self.assertIn("findings", data)

    def test_html_self_contained(self):
        findings = scan(load_config(DEMO))
        out = _render_html(findings, summarize(findings))
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("<style>", out)
        self.assertNotIn("http://", out)

    def test_missing_file_exit_2(self):
        self.assertEqual(main(["scan", "/no/such/file.json"]), 2)

    def test_fail_on_high_passes_when_only_low(self):
        import tempfile
        cfg = {"buckets": [{
            "name": "b", "acl": "private", "public_access_block": True,
            "encryption": "AES256", "versioning": False, "logging": False,
        }]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(cfg, fh)
            path = fh.name
        try:
            self.assertEqual(main(["scan", path, "--format", "json", "--fail-on", "HIGH"]), 0)
            self.assertEqual(main(["scan", path, "--format", "json", "--fail-on", "LOW"]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()


class TestHardeningEdgeCases(unittest.TestCase):
    """Tests added to cover error paths and edge cases hardened in core/cli."""

    # --- scan() robustness: non-list section values ---

    def test_scan_buckets_non_list_is_ignored(self):
        """If 'buckets' is not a list (e.g. a string), scan() must not raise."""
        result = scan({"buckets": "not-a-list"})
        self.assertIsInstance(result, list)

    def test_scan_security_groups_non_list_is_ignored(self):
        result = scan({"security_groups": 42})
        self.assertIsInstance(result, list)

    def test_scan_iam_users_non_list_is_ignored(self):
        result = scan({"iam_users": {"key": "val"}})
        self.assertIsInstance(result, list)

    def test_scan_iam_policies_non_list_is_ignored(self):
        result = scan({"iam_policies": None})
        self.assertIsInstance(result, list)

    # --- _check_iam: non-dict policy document ---

    def test_policy_with_non_dict_document_is_ignored(self):
        """A policy whose 'document' is a string must not raise."""
        config = {"iam_policies": [{"name": "bad", "document": "not-a-dict"}]}
        result = scan(config)
        # Should produce zero findings (no wildcard detected) without crashing
        wildcard = [f for f in result if f.check_id == "IAM_WILDCARD_POLICY"]
        self.assertEqual(wildcard, [])

    def test_policy_with_none_document_is_ignored(self):
        config = {"iam_policies": [{"name": "nulldoc", "document": None}]}
        result = scan(config)
        self.assertIsInstance(result, list)

    # --- CLI: malformed JSON input ---

    def test_malformed_json_exits_2(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not valid json ...")
            path = fh.name
        try:
            self.assertEqual(main(["scan", path]), 2)
        finally:
            os.unlink(path)

    def test_json_array_instead_of_object_exits_2(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        try:
            self.assertEqual(main(["scan", path]), 2)
        finally:
            os.unlink(path)

    # --- mcp_server: module compiles and imports without error ---

    def test_mcp_server_imports_cleanly(self):
        """mcp_server must import without raising (to_json no longer referenced)."""
        import importlib
        try:
            mod = importlib.import_module("cspm.mcp_server")
            self.assertTrue(callable(getattr(mod, "serve", None)))
        except ImportError as exc:
            self.fail(f"cspm.mcp_server failed to import: {exc}")


if __name__ == "__main__":
    unittest.main()
