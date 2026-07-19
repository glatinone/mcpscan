"""Tests for MCP015 (script injection), MCP016 (pwn request checkout),
MCP017 (untrusted-trigger secret reachability), MCP019 (workflow_run
token/artifact reuse), and MCP020 (missing permissions: block)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.workflow_injection import (
    MissingPermissionsBlock,
    PwnRequestCheckout,
    UntrustedTriggerSecretReachability,
    WorkflowRunArtifactReuse,
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


class TestWorkflowRunArtifactReuse(unittest.TestCase):
    rule = WorkflowRunArtifactReuse()

    def test_checkout_of_triggering_run_head_sha_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    workflows: [Build]\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.workflow_run.head_sha }}\n"
            "      - run: npm test\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP019")
        self.assertEqual(findings[0].owasp, "MCP04:2025")
        self.assertEqual(findings[0].severity.label, "critical")

    def test_checkout_of_triggering_run_head_branch_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.workflow_run.head_branch }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_download_with_triggering_run_id_fires(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    workflows: [Build]\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
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

    def test_both_shapes_in_one_file_both_fire(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.workflow_run.head_sha }}\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 2)

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
            "          run-id: ${{ github.run_id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_checkout_of_base_ref_does_not_fire(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
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

    def test_no_checkout_or_download_step_does_not_fire(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - run: echo \"build ${{ github.event.workflow_run.conclusion }}\"\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_next_step_boundary_stops_the_lookahead(self):
        text = (
            "on:\n"
            "  workflow_run:\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  post:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "      - name: unrelated\n"
            "        run: echo hi\n"
            "      - uses: some/other-action@v1\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])


class TestMissingPermissionsBlock(unittest.TestCase):
    rule = MissingPermissionsBlock()

    def test_release_action_with_no_permissions_fires(self):
        text = (
            "on:\n"
            "  push:\n"
            "    tags: ['v*']\n"
            "jobs:\n"
            "  release:\n"
            "    steps:\n"
            "      - uses: softprops/action-gh-release@v2\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP020")
        self.assertEqual(findings[0].owasp, "MCP02:2025")

    def test_git_push_with_no_permissions_fires(self):
        text = (
            "on: [push]\n"
            "jobs:\n"
            "  bump:\n"
            "    steps:\n"
            "      - run: |\n"
            "          git commit -am 'bump version'\n"
            "          git push\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_gh_release_create_with_no_permissions_fires(self):
        text = (
            "on: [push]\n"
            "jobs:\n"
            "  release:\n"
            "    steps:\n"
            "      - run: gh release create v1.0.0 --notes 'release'\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_curl_post_to_github_api_with_no_permissions_fires(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  respond:\n"
            "    steps:\n"
            "      - run: curl -X POST -H \"Authorization: token "
            "${{ secrets.GITHUB_TOKEN }}\" https://api.github.com/repos/x/y/issues/1/comments\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_explicit_top_level_permissions_suppresses_finding(self):
        text = (
            "on:\n"
            "  push:\n"
            "    tags: ['v*']\n"
            "permissions:\n"
            "  contents: write\n"
            "jobs:\n"
            "  release:\n"
            "    steps:\n"
            "      - uses: softprops/action-gh-release@v2\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_explicit_job_level_permissions_suppresses_finding(self):
        text = (
            "on:\n"
            "  push:\n"
            "    tags: ['v*']\n"
            "jobs:\n"
            "  release:\n"
            "    permissions:\n"
            "      contents: write\n"
            "    steps:\n"
            "      - uses: softprops/action-gh-release@v2\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_readonly_workflow_with_no_permissions_stays_clean(self):
        # No permissions: block, but nothing here writes anywhere — the
        # exact shape of a normal test-only CI workflow, which must never
        # be flagged by a "missing permissions" check.
        text = (
            "on: [push, pull_request]\n"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: pip install -e .\n"
            "      - run: python -m unittest discover -s tests\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])

    def test_readonly_gh_command_stays_clean(self):
        text = (
            "on: [pull_request]\n"
            "jobs:\n"
            "  check:\n"
            "    steps:\n"
            "      - run: gh pr view ${{ github.event.pull_request.number }}\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
