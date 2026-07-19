"""Tests for MCP015 (script injection), MCP016 (pwn request checkout),
MCP017 (untrusted-trigger secret reachability), and MCP019 (workflow_run
artifact reachability)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.workflow_injection import (
    PwnRequestCheckout,
    UntrustedTriggerSecretReachability,
    WorkflowRunArtifactReachability,
    WorkflowScriptInjection,
)


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


class TestUntrustedTriggerSecretReachability(unittest.TestCase):
    rule = UntrustedTriggerSecretReachability()

    def test_issue_comment_trigger_with_custom_secret_and_no_gate_fires(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "    types: [created]\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - run: curl -H \"Auth: ${{ secrets.DEPLOY_TOKEN }}\" x\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP017")
        self.assertEqual(findings[0].owasp, "MCP02:2025")

    def test_pull_request_target_with_custom_secret_and_no_gate_fires(self):
        text = (
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: echo \"${{ secrets.NPM_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_list_form_trigger_fires(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - run: echo \"${{ secrets.DEPLOY_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_github_token_only_does_not_fire(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - run: echo \"${{ secrets.GITHUB_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_environment_gate_suppresses_finding(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "jobs:\n"
            "  respond:\n"
            "    environment: comment-bot-approval\n"
            "    steps:\n"
            "      - run: echo \"${{ secrets.DEPLOY_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_author_association_gate_suppresses_finding(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), "
            "github.event.comment.author_association)\n"
            "        run: echo \"${{ secrets.DEPLOY_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_actor_allowlist_gate_suppresses_finding(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - if: github.actor == 'trusted-bot'\n"
            "        run: echo \"${{ secrets.DEPLOY_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_trusted_trigger_does_not_fire(self):
        text = (
            "on:\n"
            "  pull_request:\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: echo \"${{ secrets.NPM_TOKEN }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_no_secret_reference_does_not_fire(self):
        text = (
            "on:\n"
            "  issue_comment:\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])


class TestWorkflowRunArtifactReachability(unittest.TestCase):
    rule = WorkflowRunArtifactReachability()

    def test_download_with_triggering_run_id_and_no_permissions_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    workflows: [Build]\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          name: build-output\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
            "      - run: ./build-output/script.sh\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP019")
        self.assertEqual(findings[0].owasp, "MCP02:2025")

    def test_third_party_download_action_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: dawidd6/action-download-artifact@v3\n"
            "        with:\n"
            "          run_id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_readonly_permissions_block_suppresses_finding(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_empty_permissions_block_suppresses_finding(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "permissions: {}\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_write_all_permissions_still_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_job_level_write_permission_still_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    permissions:\n"
            "      contents: write\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_download_without_triggering_run_id_does_not_fire(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          name: same-run-artifact\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_non_workflow_run_trigger_does_not_fire(self):
        text = (
            "on:\n"
            "  push:\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_no_artifact_download_step_does_not_fire(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - run: echo done\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
