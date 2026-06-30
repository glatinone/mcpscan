"""Tests for the JSON-RPC MCP server surface."""

import json
import os
import unittest

from mcpscan.mcp_server import handle_request

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vulnerable")


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "mcpscan")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list_exposes_scan(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["scan"])

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


if __name__ == "__main__":
    unittest.main()
