"""Tests for the JSON-RPC MCP server surface."""

import json
import os
import tempfile
import unittest
from unittest import mock

from mcpscan.mcp_server import handle_request

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vulnerable")

VULN_REMOTE_SERVER = json.dumps({
    "mcpServers": {
        "internal-tool": {"url": "http://10.0.0.5:8080/mcp"},
    }
})


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "mcpscan")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list_exposes_scan_and_discover(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["scan", "discover"])

    def test_notifications_get_no_response(self):
        self.assertIsNone(handle_request({"method": "notifications/initialized"}))

    def test_unknown_method_errors(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 9, "method": "nope"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_scan_call_returns_report(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "scan", "arguments": {"path": VULN, "min_severity": "high"}},
        })
        self.assertFalse(resp["result"]["isError"])
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["tool"], "mcpscan")
        self.assertTrue(payload["findings"])

    def test_unknown_tool_errors(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "bogus", "arguments": {}},
        })
        self.assertIn("error", resp)

    def test_discover_call_returns_report_per_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            cursor_dir = os.path.join(tmp, ".cursor")
            os.makedirs(cursor_dir)
            with open(os.path.join(cursor_dir, "mcp.json"), "w", encoding="utf-8") as fh:  # mcpscan: ignore[MCP007]
                fh.write(VULN_REMOTE_SERVER)

            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}), \
                 mock.patch("sys.platform", "linux"):
                resp = handle_request({
                    "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "discover", "arguments": {"min_severity": "high"}},
                })

        self.assertFalse(resp["result"]["isError"])
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["mode"], "discover")
        cursor_loc = next(loc for loc in payload["locations"] if loc["client"] == "Cursor (global)")
        self.assertTrue(cursor_loc["found"])
        self.assertEqual(cursor_loc["findings"][0]["rule_id"], "MCP012")

    def test_discover_call_respects_min_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": os.path.join(tmp, "AppData")}), \
                 mock.patch("sys.platform", "linux"):
                resp = handle_request({
                    "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                    "params": {"name": "discover", "arguments": {"min_severity": "critical"}},
                })

        self.assertFalse(resp["result"]["isError"])
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
