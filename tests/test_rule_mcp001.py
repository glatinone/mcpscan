"""Tests for MCP001 (command injection sinks), mcpscan/rules/command_injection.py.

Regression coverage for a false positive found while scanning real-world MCP
server repos: JS_SINKS used an unanchored `child_process.` prefix before the
exec/spawn alternation, so the pattern matched starting right after ANY
preceding dot -- so a plain RegExp method call, unrelated to child_process,
was flagged as "child process execution". Found in jmrplens/gitlab-mcp-server's
site/scripts/check-chips.mjs.
"""

import os
import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.command_injection import CommandInjection


def _file(text, relpath="server.mjs", kind="source"):
    return FileInfo(
        relpath=relpath, abspath=relpath, text=text, kind=kind, in_dot_claude=False
    )


class TestCommandInjectionJsSinks(unittest.TestCase):
    def setUp(self):
        self.rule = CommandInjection()

    def test_regex_exec_is_not_flagged(self):
        findings = self.rule.check([
            _file('const text = /^\\s+-\\s+text:\\s*(.+)$/.exec(line);')
        ])
        self.assertEqual(findings, [])

    def test_arbitrary_object_exec_method_is_not_flagged(self):
        findings = self.rule.check([_file("const m = pattern.exec(input);")])
        self.assertEqual(findings, [])

    def test_child_process_exec_is_still_flagged(self):
        findings = self.rule.check([
            _file('child_process.exec(`rm -rf ${userInput}`);')
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP001")

    def test_bare_exec_from_destructured_import_is_still_flagged(self):
        findings = self.rule.check([
            _file(
                "const { exec } = require('child_process');\n"
                "exec(`ls ${dir}`);\n"  # mcpscan: ignore[MCP001]
            )
        ])
        self.assertEqual(len(findings), 1)

    def test_bare_execsync_is_still_flagged(self):
        findings = self.rule.check([
            _file("execSync(`git clone ${repoUrl}`);")
        ])
        self.assertEqual(len(findings), 1)

    def test_spawn_on_unrelated_object_is_not_flagged(self):
        findings = self.rule.check([_file("const child = worker.spawn(task);")])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
