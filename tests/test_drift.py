"""Tests for MCP014: remote MCP server domain drift since the last --discover run."""

import json
import os
import tempfile
import unittest
from unittest import mock

from mcpscan import cli
from mcpscan.discover import run_discovery
from mcpscan.drift import check_drift, default_baseline_path


def _server_json(url: str, *, authed: bool = True) -> str:
    cfg = {"url": url}
    if authed:
        cfg["headers"] = {"Authorization": "Bearer ${INTERNAL_TOOL_TOKEN}"}
    return json.dumps({"mcpServers": {"internal-tool": cfg}})


LOCAL_STDIO_SERVER = json.dumps({
    "mcpServers": {"local-tool": {"command": "python", "args": ["server.py"]}},
})


def _write_cursor_config(tmp_dir: str, content: str) -> None:
    cursor_dir = os.path.join(tmp_dir, ".cursor")
    os.makedirs(cursor_dir, exist_ok=True)
    with open(os.path.join(cursor_dir, "mcp.json"), "w", encoding="utf-8") as fh:  # mcpscan: ignore[MCP007]
        fh.write(content)


def _discover_in(tmp: str):
    with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}):
        return run_discovery(platform="linux")


class TestFirstSighting(unittest.TestCase):
    def test_first_scan_records_baseline_with_no_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)

            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            self.assertEqual([f.rule_id for f in cursor.report.findings], [])

            with open(baseline_path, encoding="utf-8") as fh:
                saved = json.load(fh)
            key = f"{cursor.location.path}::internal-tool"
            self.assertEqual(saved["servers"][key], "api.example.com")

    def test_no_baseline_file_written_when_nothing_to_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, LOCAL_STDIO_SERVER)
            baseline_path = os.path.join(tmp, "baseline.json")

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)

            self.assertFalse(os.path.exists(baseline_path))


class TestDomainChange(unittest.TestCase):
    def test_changed_domain_raises_mcp014_and_updates_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")

            discovery = _discover_in(tmp)
            key = f"{next(r for r in discovery.results if r.location.client == 'Cursor (global)').location.path}::internal-tool"
            with open(baseline_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "servers": {key: "api.example.com"}}, fh)

            # Same server name, domain silently changed underneath it.
            _write_cursor_config(tmp, _server_json("https://evil-mirror.example.net/mcp"))
            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)

            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            drift_findings = [f for f in cursor.report.findings if f.rule_id == "MCP014"]
            self.assertEqual(len(drift_findings), 1)
            self.assertIn("api.example.com", drift_findings[0].detail)
            self.assertIn("evil-mirror.example.net", drift_findings[0].detail)
            self.assertEqual(drift_findings[0].severity.label, "high")
            self.assertEqual(drift_findings[0].owasp, "MCP04:2025")

            with open(baseline_path, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["servers"][key], "evil-mirror.example.net")

    def test_alerts_once_then_trusts_the_new_domain(self):
        """A changed domain fires once; running again against the same (new)
        domain must not re-fire — 'alert once, then trust the new state.'"""
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")
            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)  # establishes baseline

            _write_cursor_config(tmp, _server_json("https://new-region.example.com/mcp"))
            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)  # fires once
            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            self.assertEqual(len([f for f in cursor.report.findings if f.rule_id == "MCP014"]), 1)

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)  # same domain again: quiet
            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            self.assertEqual([f for f in cursor.report.findings if f.rule_id == "MCP014"], [])


class TestUnchangedDomain(unittest.TestCase):
    def test_same_domain_across_runs_produces_no_finding_or_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)
            with open(baseline_path, encoding="utf-8") as fh:
                before = fh.read()

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)
            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            self.assertEqual([f for f in cursor.report.findings if f.rule_id == "MCP014"], [])

            with open(baseline_path, encoding="utf-8") as fh:
                after = fh.read()
            self.assertEqual(before, after)


class TestLocalServersOutOfScope(unittest.TestCase):
    def test_stdio_server_never_enters_the_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, LOCAL_STDIO_SERVER)
            baseline_path = os.path.join(tmp, "baseline.json")
            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)
            self.assertFalse(os.path.exists(baseline_path))


class TestMalformedBaseline(unittest.TestCase):
    def test_corrupt_baseline_file_degrades_to_empty_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")
            with open(baseline_path, "w", encoding="utf-8") as fh:
                fh.write("{not valid json")

            discovery = _discover_in(tmp)
            check_drift(discovery, baseline_path=baseline_path)  # must not raise

            cursor = next(r for r in discovery.results if r.location.client == "Cursor (global)")
            self.assertEqual([f for f in cursor.report.findings if f.rule_id == "MCP014"], [])


class TestDefaultBaselinePath(unittest.TestCase):
    def test_env_var_override_wins(self):
        with mock.patch.dict(os.environ, {"MCPSCAN_BASELINE_PATH": "/tmp/custom-baseline.json"}):
            self.assertEqual(default_baseline_path(), "/tmp/custom-baseline.json")

    def test_falls_back_to_home_based_path(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/tester", "USERPROFILE": "", "APPDATA": ""}, clear=False):
            os.environ.pop("MCPSCAN_BASELINE_PATH", None)
            path = default_baseline_path()
        self.assertTrue(path.startswith("/home/tester"))
        self.assertTrue(path.endswith(os.path.join(".mcpscan", "discover_baseline.json")))


class TestListRulesIncludesMcp014(unittest.TestCase):
    def test_list_rules_shows_mcp014(self):
        output = cli.list_rules()
        self.assertIn("MCP014", output)
        self.assertIn("MCP04:2025", output)


class TestDiscoverCliRunsDrift(unittest.TestCase):
    def test_domain_change_across_two_discover_invocations_affects_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, _server_json("https://api.example.com/mcp"))
            baseline_path = os.path.join(tmp, "baseline.json")

            env = {
                "HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData"),
                "MCPSCAN_BASELINE_PATH": baseline_path,
            }
            with mock.patch.dict(os.environ, env), mock.patch("sys.platform", "linux"):
                first_exit = cli.main(["--discover", "--json", "--min-severity", "high"])
            self.assertEqual(first_exit, cli.EXIT_OK)  # clean, authed server, no baseline yet

            _write_cursor_config(tmp, _server_json("https://evil-mirror.example.net/mcp"))
            with mock.patch.dict(os.environ, env), mock.patch("sys.platform", "linux"):
                second_exit = cli.main(["--discover", "--json", "--min-severity", "high"])
            self.assertEqual(second_exit, cli.EXIT_FINDINGS)  # MCP014 fires, severity high


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
