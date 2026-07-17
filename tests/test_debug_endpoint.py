"""Tests for MCP018 (unauthenticated connect/exec endpoint on a server bound
to all interfaces)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.debug_endpoint import UnauthenticatedConnectExecEndpoint


def _file(text: str, relpath: str = "server.py") -> FileInfo:
    return FileInfo(relpath=relpath, abspath="x", text=text, kind="source", in_dot_claude=False)


class TestUnauthenticatedConnectExecEndpoint(unittest.TestCase):
    rule = UnauthenticatedConnectExecEndpoint()

    def test_bind_all_plus_unauthenticated_connect_endpoint_fires(self):
        text = (
            "app.run(host=\"0.0.0.0\", port=6274)\n"
            "\n"
            "@app.route(\"/api/connect\", methods=[\"POST\"])\n"
            "def connect():\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen(payload[\"command\"], payload.get(\"args\", []))\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP018")
        self.assertEqual(findings[0].line, 6)

    def test_node_listen_with_no_host_fires(self):
        text = (
            "const app = express();\n"
            "app.listen(PORT);\n"
            "\n"
            "app.post(\"/connect\", (req, res) => {\n"
            "  const payload = req.body;\n"
            "  spawn(payload.command, payload.args);\n"  # mcpscan: ignore[MCP018]
            "});\n"
        )
        findings = self.rule.check([_file(text, relpath="index.js")])
        self.assertEqual(len(findings), 1)

    def test_localhost_bind_does_not_fire(self):
        text = (
            "app.run(host=\"127.0.0.1\", port=6274)\n"
            "\n"
            "@app.route(\"/api/connect\", methods=[\"POST\"])\n"
            "def connect():\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen(payload[\"command\"], payload.get(\"args\", []))\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_auth_check_in_handler_does_not_fire(self):
        text = (
            "app.run(host=\"0.0.0.0\", port=6274)\n"
            "\n"
            "@app.route(\"/api/connect\", methods=[\"POST\"])\n"
            "def connect():\n"
            "    if not authenticate(request.headers.get(\"Authorization\")):\n"
            "        return \"unauthorized\", 401\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen(payload[\"command\"], payload.get(\"args\", []))\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_unrelated_route_path_does_not_fire(self):
        text = (
            "app.run(host=\"0.0.0.0\", port=6274)\n"
            "\n"
            "@app.route(\"/api/status\", methods=[\"GET\"])\n"
            "def status():\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen(payload[\"command\"])\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_hardcoded_argv_spawn_does_not_fire(self):
        text = (
            "app.run(host=\"0.0.0.0\", port=6274)\n"
            "\n"
            "@app.route(\"/api/connect\", methods=[\"POST\"])\n"
            "def connect():\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen([\"ls\", \"-la\"])\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_no_bind_all_anywhere_does_not_fire(self):
        text = (
            "@app.route(\"/api/connect\", methods=[\"POST\"])\n"
            "def connect():\n"
            "    payload = request.get_json()\n"
            "    return subprocess.Popen(payload[\"command\"], payload.get(\"args\", []))\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_bind_all_with_no_connect_route_does_not_fire(self):
        text = (
            "app.run(host=\"0.0.0.0\", port=6274)\n"
            "\n"
            "@app.route(\"/api/status\", methods=[\"GET\"])\n"
            "def status():\n"
            "    return \"ok\"\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_out_of_scope_extension_does_not_fire(self):
        text = (
            "{\"host\": \"0.0.0.0\", \"route\": \"/api/connect\", "
            "\"command\": \"request.get_json()\"}\n"
        )
        self.assertEqual(self.rule.check([_file(text, relpath="config.json")]), [])


if __name__ == "__main__":
    unittest.main()
