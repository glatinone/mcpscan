"""Tests for MCP015 (script injection) and MCP016 (pwn request checkout)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.workflow_injection import PwnRequestCheckout, WorkflowScriptInjection


def _file(text: str, relpath: str = ".github/workflows/ci.yml") -> FileInfo:
    return FileInfo(relpath=relpath, abspath="x", text=text, kind="config", in_dot_claude=False)


class TestWorkflowScriptInjection(unittest.TestCase):
    rule = WorkflowScriptInjection()

    def test_direct_interpolation_in_block_run_step_fires(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  triage:\n"
            "    steps:\n"
            "      - name: Handle it\n"
            "        run: |\n"
            "          echo \"${{ github.event.issue.title }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 7)
        self.assertEqual(findings[0].rule_id, "MCP015")

    def test_direct_interpolation_in_single_line_run_fires(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  triage:\n"
            "    steps:\n"
            "      - run: echo \"${{ github.event.comment.body }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_env_var_indirection_does_not_fire(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  triage:\n"
            "    steps:\n"
            "      - name: Handle it safely\n"
            "        env:\n"
            "          TITLE: ${{ github.event.issue.title }}\n"
            "        run: |\n"
            "          echo \"$TITLE\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_github_script_block_is_also_an_execution_sink(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  triage:\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            core.info(`${{ github.event.issue.body }}`)\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_trusted_context_is_not_flagged(self):
        text = (
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: echo \"${{ matrix.python-version }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_non_workflow_yaml_is_out_of_scope(self):
        text = 'run: echo "${{ github.event.issue.title }}"\n'
        findings = self.rule.check([_file(text, relpath="smithery.yaml")])
        self.assertEqual(findings, [])

    def test_next_step_ends_the_block_scan(self):
        # A second step's own `run:` shouldn't be treated as a continuation of
        # the first step's block scalar.
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  triage:\n"
            "    steps:\n"
            "      - name: safe step\n"
            "        run: |\n"
            "          echo hi\n"
            "      - name: unsafe step\n"
            "        run: echo \"${{ github.event.issue.title }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 9)


class TestPwnRequestCheckout(unittest.TestCase):
    rule = PwnRequestCheckout()

    def test_pull_request_target_checking_out_fork_head_fires(self):
        text = (
            "on:\n"
            "  pull_request_target:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP016")
        self.assertEqual(findings[0].severity.label, "critical")

    def test_pull_request_target_in_list_form_fires(self):
        text = (
            "on: [push, pull_request_target]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.ref }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_pull_request_trigger_without_target_does_not_fire(self):
        text = (
            "on:\n"
            "  pull_request:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_pull_request_target_without_fork_checkout_does_not_fire(self):
        text = (
            "on:\n"
            "  pull_request_target:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_next_step_boundary_stops_the_lookahead(self):
        # The `ref:` line belongs to a later, unrelated step — the lookahead
        # must stop at the checkout step's own boundary and never reach it.
        text = (
            "on:\n"
            "  pull_request_target:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - name: unrelated step\n"
            "        run: echo hi\n"
            "      - uses: some/other-action@v1\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
