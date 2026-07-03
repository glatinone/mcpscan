"""End-to-end and per-rule tests. Runs under pytest or `python -m unittest`."""

import os
import unittest

from mcpscan.findings import Severity
from mcpscan.report import render_json, render_sarif
from mcpscan.scanner import scan

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vulnerable")
CLEAN = os.path.join(HERE, "fixtures", "clean")


class TestVulnerableFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(VULN)
        cls.ids = {f.rule_id for f in cls.report.findings}

    def test_every_rule_fires(self):
        for rid in ("MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
                    "MCP006", "MCP007", "MCP008", "MCP009", "MCP010", "MCP011",
                    "MCP012"):
            self.assertIn(rid, self.ids, f"{rid} did not fire on the vulnerable fixture")

    def test_tool_poisoning_is_critical(self):
        poison = [f for f in self.report.findings if f.rule_id == "MCP002"]
        self.assertTrue(poison)
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in poison))

    def test_secret_is_redacted(self):
        secret = [f for f in self.report.findings if f.rule_id == "MCP005"]
        self.assertTrue(secret)
        self.assertNotIn("FAKEKEYFORTESTS", secret[0].snippet)
        self.assertIn("REDACTED", secret[0].snippet)

    def test_has_findings_at_high(self):
        self.assertTrue(self.report.at_or_above(Severity.HIGH))


class TestCleanFixture(unittest.TestCase):
    def test_clean_is_clean(self):
        report = scan(CLEAN)
        self.assertEqual(report.findings, [], f"unexpected findings: {report.findings}")


class TestDenyBlockLines(unittest.TestCase):
    def test_multiline_deny_array_is_fully_covered(self):
        from mcpscan.rules.base import deny_block_lines

        lines = [
            '{',
            '  "permissions": {',
            '    "allow": ["Bash(git status)"],',
            '    "deny": [',
            '      "Bash(*)",',
            '      "WebFetch(domain:*)"',
            '    ]',
            '  }',
            '}',
        ]
        covered = deny_block_lines(lines)
        # Every line of the deny array (open, both entries, close) must be covered,
        # not just the first line or two after the "deny" key.
        self.assertEqual(covered, {4, 5, 6, 7})

    def test_single_line_deny_array(self):
        from mcpscan.rules.base import deny_block_lines

        self.assertEqual(deny_block_lines(['"deny": []']), {1})


class TestWebFetchDomainRule(unittest.TestCase):
    @staticmethod
    def _findings(text):
        from mcpscan.loaders import FileInfo
        from mcpscan.rules.webfetch_domain import OverBroadWebFetchDomain

        f = FileInfo(relpath=".claude/settings.json", abspath="x", text=text,
                     kind="config", in_dot_claude=True)
        return OverBroadWebFetchDomain().check([f])

    def test_wildcard_domain_is_high(self):
        out = self._findings('"WebFetch(domain:*)"')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.HIGH)

    def test_bare_tld_wildcard_is_medium(self):
        out = self._findings('"WebFetch(domain:*.com)"')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.MEDIUM)

    def test_bare_webfetch_with_no_domain_is_flagged(self):
        out = self._findings('"WebFetch"')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.HIGH)

    def test_scoped_domain_is_clean(self):
        out = self._findings('"WebFetch(domain:api.example.com)"')
        self.assertEqual(out, [])

    def test_denied_wildcard_is_not_flagged(self):
        text = '"deny": [\n  "WebFetch(domain:*)"\n]'
        out = self._findings(text)
        self.assertEqual(out, [])


class TestAuthGapsRule(unittest.TestCase):
    @staticmethod
    def _findings(payload):
        import json as json_mod

        from mcpscan.loaders import FileInfo
        from mcpscan.rules.auth_gaps import AuthGaps

        text = json_mod.dumps(payload)
        f = FileInfo(relpath="claude_desktop_config.json", abspath="x", text=text,
                     kind="manifest", in_dot_claude=False)
        return AuthGaps().check([f])

    def test_remote_server_with_no_auth_is_flagged(self):
        out = self._findings({"mcpServers": {"public": {"url": "https://example.com/mcp"}}})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.HIGH)

    def test_hardcoded_bearer_token_is_flagged(self):
        out = self._findings({"mcpServers": {"billing": {
            "url": "https://example.com/mcp",
            "headers": {"Authorization": "Bearer sk-live-51H8xJ2eKq9pT7vN3mZ8cQ1wR6yU4iO0aS5dF"},
        }}})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.MEDIUM)

    def test_env_interpolated_token_is_clean(self):
        out = self._findings({"mcpServers": {"internal": {
            "url": "https://example.com/mcp",
            "headers": {"Authorization": "Bearer ${MCP_TOKEN}"},
        }}})
        self.assertEqual(out, [])

    def test_local_stdio_server_is_out_of_scope(self):
        out = self._findings({"mcpServers": {"local": {
            "command": "npx", "args": ["-y", "@example/server"],
        }}})
        self.assertEqual(out, [])


class TestSuppression(unittest.TestCase):
    def test_inline_and_glob_suppression(self):
        from mcpscan.findings import Finding
        from mcpscan.suppress import is_suppressed, path_ignored

        lines = {
            "a.py": ["os.system(x)  # mcpscan: ignore", "os.system(y)  # mcpscan: ignore[MCP001]"],
            "b.py": ["os.system(z)  # mcpscan: ignore[MCP999]"],
        }
        f1 = Finding("MCP001", "t", Severity.HIGH, "a.py", 1)
        f2 = Finding("MCP001", "t", Severity.HIGH, "a.py", 2)
        f3 = Finding("MCP001", "t", Severity.HIGH, "b.py", 1)  # wrong id -> not suppressed
        self.assertTrue(is_suppressed(f1, lines))
        self.assertTrue(is_suppressed(f2, lines))
        self.assertFalse(is_suppressed(f3, lines))

        self.assertTrue(path_ignored("vendor/x.py", ["vendor"]))
        self.assertTrue(path_ignored("a/b/secrets.json", ["secrets.json"]))
        self.assertFalse(path_ignored("src/app.py", ["vendor"]))


class TestCli(unittest.TestCase):
    @staticmethod
    def _run(argv):
        import contextlib
        import io
        from mcpscan.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return main(argv)

    def test_list_rules(self):
        from mcpscan.cli import list_rules
        out = list_rules()
        for rid in ("MCP001", "MCP011", "MCP012"):
            self.assertIn(rid, out)
        self.assertIn("12 rules", out)

    def test_main_clean_exit_zero(self):
        self.assertEqual(self._run([CLEAN, "--no-color"]), 0)

    def test_main_vulnerable_exit_one(self):
        self.assertEqual(self._run([VULN, "--no-color", "--min-severity", "high"]), 1)

    def test_main_missing_path_exit_two(self):
        self.assertEqual(self._run(["does-not-exist-xyz", "--no-color"]), 2)


class TestRenderers(unittest.TestCase):
    def test_json_and_sarif_are_serialisable(self):
        report = scan(VULN)
        import json
        json.loads(render_json(report))
        sarif = json.loads(render_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(report.findings))


if __name__ == "__main__":
    unittest.main()
