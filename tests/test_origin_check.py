"""Tests for MCP022 (loopback-bound server accepts cross-origin requests
with no Origin check)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.origin_check import LoopbackBridgeNoOriginCheck


def _file(text: str, relpath: str = "bridge.js") -> FileInfo:
    return FileInfo(relpath=relpath, abspath="x", text=text, kind="source", in_dot_claude=False)


class TestLoopbackBridgeNoOriginCheck(unittest.TestCase):
    rule = LoopbackBridgeNoOriginCheck()

    # --- permissive CORS path ------------------------------------------------

    def test_loopback_bind_plus_bare_express_cors_fires(self):
        text = (
            "app.listen(3000, '127.0.0.1');\n"
            "app.use(cors());\n"  # mcpscan: ignore[MCP022]
        )
        findings = self.rule.check([_file(text, relpath="server.js")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP022")
        self.assertEqual(findings[0].line, 2)

    def test_loopback_bind_plus_bare_flask_cors_fires(self):
        text = (
            "app.run(host='127.0.0.1', port=8765)\n"
            "CORS(app)\n"  # mcpscan: ignore[MCP022]
        )
        findings = self.rule.check([_file(text, relpath="server.py")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)

    def test_loopback_bind_plus_wildcard_header_fires(self):
        text = (
            "app.listen(3000, 'localhost');\n"
            "res.setHeader('Access-Control-Allow-Origin', '*');\n"  # mcpscan: ignore[MCP022]
        )
        findings = self.rule.check([_file(text, relpath="server.js")])
        self.assertEqual(len(findings), 1)

    def test_loopback_bind_plus_scoped_cors_does_not_fire(self):
        text = (
            "app.run(host='127.0.0.1', port=8765)\n"
            "CORS(app, origins=['https://trusted.example.com'])\n"
        )
        self.assertEqual(self.rule.check([_file(text, relpath="server.py")]), [])

    def test_bind_all_does_not_fire_cors_path(self):
        # 0.0.0.0 is MCP018's territory (bind-all), not this rule's.
        text = (
            "app.run(host='0.0.0.0', port=8765)\n"
            "CORS(app)\n"  # mcpscan: ignore[MCP022]
        )
        self.assertEqual(self.rule.check([_file(text, relpath="server.py")]), [])

    # --- WebSocket path -------------------------------------------------------

    def test_loopback_ws_no_origin_check_fires(self):
        text = (
            "const wss = new WebSocketServer({ host: '127.0.0.1', port: 9000 });\n"
            "wss.on('connection', (ws, req) => {\n"
            "  ws.on('message', (data) => runDesktopCommand(JSON.parse(data)));\n"
            "});\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)

    def test_loopback_ws_with_origin_check_does_not_fire(self):
        text = (
            "const wss = new WebSocketServer({ host: '127.0.0.1', port: 9000 });\n"
            "wss.on('connection', (ws, req) => {\n"
            "  if (req.headers.origin !== 'https://trusted.example.com') { ws.close(); return; }\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_no_loopback_bind_at_all_does_not_fire(self):
        text = (
            "wss.on('connection', (ws, req) => {\n"
            "  ws.on('message', (data) => runDesktopCommand(JSON.parse(data)));\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_python_extension_out_of_scope_for_ws_path(self):
        # The .on('connection', ...) shape is a JS-ecosystem concept; a .py
        # file with lookalike text should never match the WebSocket path.
        text = (
            "host = '127.0.0.1'\n"
            "def on(event, handler):\n"
            "    pass\n"
            "on('connection', handle)\n"
        )
        self.assertEqual(self.rule.check([_file(text, relpath="server.py")]), [])

    def test_non_source_extension_out_of_scope(self):
        text = (
            "app.listen(3000, '127.0.0.1');\n"
            "app.use(cors());\n"  # mcpscan: ignore[MCP022]
        )
        self.assertEqual(self.rule.check([_file(text, relpath="notes.txt")]), [])


if __name__ == "__main__":
    unittest.main()
