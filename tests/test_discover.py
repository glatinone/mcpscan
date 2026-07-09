"""Tests for --discover: known MCP client config locations on this machine."""

import json
import os
import tempfile
import unittest
from unittest import mock

from mcpscan import cli
from mcpscan.discover import known_locations, run_discovery


VULN_REMOTE_SERVER = json.dumps({
    "mcpServers": {
        "internal-tool": {"url": "http://10.0.0.5:8080/mcp"},
    }
})

CLEAN_REMOTE_SERVER = json.dumps({
    "mcpServers": {
        "internal-tool": {
            "url": "http://10.0.0.5:8080/mcp",
            "headers": {"Authorization": "Bearer ${INTERNAL_TOOL_TOKEN}"},
        },
    }
})


def _write_cursor_config(tmp_dir: str, content: str) -> None:
    """Write a fake global Cursor config under a tempdir. tmp_dir is always a
    pytest/tempfile-owned directory, never caller-controlled input.
    """
    cursor_dir = os.path.join(tmp_dir, ".cursor")
    os.makedirs(cursor_dir)
    with open(os.path.join(cursor_dir, "mcp.json"), "w", encoding="utf-8") as fh:  # mcpscan: ignore[MCP007]
        fh.write(content)


class TestKnownLocations(unittest.TestCase):
    def test_covers_all_five_clients_on_every_platform(self):
        for plat in ("win32", "darwin", "linux"):
            locs = known_locations(platform=plat)
            clients = {loc.client for loc in locs}
            self.assertEqual(len(locs), 5, f"expected 5 locations on {plat}, got {len(locs)}")
            self.assertIn("Claude Desktop", clients)
            self.assertIn("Claude Code CLI (user)", clients)
            self.assertIn("Cursor (global)", clients)
            self.assertIn("VS Code (user)", clients)
            self.assertIn("Windsurf", clients)

    def test_paths_differ_per_platform_for_appdata_based_clients(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/tester", "APPDATA": "C:\\Users\\tester\\AppData\\Roaming"}):
            win = {loc.client: loc.path for loc in known_locations(platform="win32")}
            mac = {loc.client: loc.path for loc in known_locations(platform="darwin")}
            linux = {loc.client: loc.path for loc in known_locations(platform="linux")}
        self.assertNotEqual(win["Claude Desktop"], mac["Claude Desktop"])
        self.assertNotEqual(mac["Claude Desktop"], linux["Claude Desktop"])
        # Project-agnostic clients (no OS-specific branch) resolve identically.
        self.assertEqual(win["Cursor (global)"], mac["Cursor (global)"])

    def test_resolves_against_patched_home_not_real_home(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/tester", "USERPROFILE": "", "APPDATA": ""}, clear=False):
            locs = {loc.client: loc.path for loc in known_locations(platform="linux")}
        self.assertTrue(locs["Cursor (global)"].startswith("/home/tester"))


class TestRunDiscovery(unittest.TestCase):
    def test_not_present_locations_are_recorded_without_a_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}):
                discovery = run_discovery(platform="linux")
        self.assertEqual(discovery.found_count, 0)
        self.assertEqual(discovery.all_findings(), [])
        for r in discovery.results:
            self.assertFalse(r.found)
            self.assertIsNone(r.report)

    def test_present_location_is_scanned_with_the_normal_rule_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, VULN_REMOTE_SERVER)

            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}):
                discovery = run_discovery(platform="linux")

        cursor_result = next(r for r in discovery.results if r.location.client == "Cursor (global)")
        self.assertTrue(cursor_result.found)
        self.assertTrue(cursor_result.report.findings)
        self.assertEqual(cursor_result.report.findings[0].rule_id, "MCP012")
        self.assertEqual(discovery.found_count, 1)
        self.assertEqual(len(discovery.all_findings()), 1)

    def test_clean_config_at_a_known_location_produces_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, CLEAN_REMOTE_SERVER)

            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}):
                discovery = run_discovery(platform="linux")

        cursor_result = next(r for r in discovery.results if r.location.client == "Cursor (global)")
        self.assertTrue(cursor_result.found)
        self.assertEqual(cursor_result.report.findings, [])


class TestDiscoverCli(unittest.TestCase):
    def test_discover_json_exits_nonzero_when_findings_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_cursor_config(tmp, VULN_REMOTE_SERVER)

            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}), \
                 mock.patch("sys.platform", "linux"):
                exit_code = cli.main(["--discover", "--json", "--min-severity", "high"])
        self.assertEqual(exit_code, cli.EXIT_FINDINGS)

    def test_discover_sarif_is_rejected(self):
        exit_code = cli.main(["--discover", "--format", "sarif"])
        self.assertEqual(exit_code, cli.EXIT_ERROR)

    def test_discover_with_fix_is_rejected(self):
        exit_code = cli.main(["--discover", "--fix"])
        self.assertEqual(exit_code, cli.EXIT_ERROR)

    def test_discover_with_no_locations_present_exits_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}), \
                 mock.patch("sys.platform", "linux"):
                exit_code = cli.main(["--discover"])
        self.assertEqual(exit_code, cli.EXIT_OK)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
