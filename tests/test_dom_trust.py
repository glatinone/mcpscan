"""Tests for MCP021 (click handler dispatches a privileged action with no
event.isTrusted check)."""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.dom_trust import UntrustedClickPrivilegedAction


def _file(text: str, relpath: str = "content.js") -> FileInfo:
    return FileInfo(relpath=relpath, abspath="x", text=text, kind="source", in_dot_claude=False)


class TestUntrustedClickPrivilegedAction(unittest.TestCase):
    rule = UntrustedClickPrivilegedAction()

    def test_dataset_read_plus_extension_messaging_fires(self):
        text = (
            "button.addEventListener('click', (event) => {\n"
            "  const taskId = button.dataset.taskId;\n"
            "  chrome.runtime.sendMessage({type: 'run-task', taskId});\n"
            "});\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP021")
        self.assertEqual(findings[0].line, 3)

    def test_get_attribute_plus_browser_messaging_fires(self):
        text = (
            "el.addEventListener('click', function(event) {\n"
            "  const taskId = el.getAttribute('data-task-id');\n"
            "  browser.runtime.sendMessage({taskId});\n"
            "});\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_approve_call_as_sink_fires(self):
        text = (
            "btn.addEventListener('click', (event) => {\n"
            "  const action = btn.dataset.action;\n"
            "  approveAction(action);\n"
            "});\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_is_trusted_check_does_not_fire(self):
        text = (
            "button.addEventListener('click', (event) => {\n"
            "  if (!event.isTrusted) return;\n"
            "  const taskId = button.dataset.taskId;\n"
            "  chrome.runtime.sendMessage({type: 'run-task', taskId});\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_no_element_data_read_does_not_fire(self):
        text = (
            "button.addEventListener('click', (event) => {\n"
            "  chrome.runtime.sendMessage({type: 'ping'});\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_no_privileged_sink_does_not_fire(self):
        text = (
            "button.addEventListener('click', (event) => {\n"
            "  const taskId = button.dataset.taskId;\n"
            "  console.log(taskId);\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_onclick_assignment_form_fires(self):
        text = (
            "el.onclick = function(event) {\n"
            "  const taskId = el.dataset.taskId;\n"
            "  chrome.runtime.sendMessage({taskId});\n"
            "};\n"
        )
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)

    def test_no_click_listener_at_all_does_not_fire(self):
        text = (
            "function run(taskId) {\n"
            "  chrome.runtime.sendMessage({taskId});\n"
            "}\n"
        )
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_out_of_scope_extension_does_not_fire(self):
        text = (
            "button.addEventListener('click', (event) => {\n"
            "  const taskId = button.dataset.taskId;\n"
            "  chrome.runtime.sendMessage({taskId});\n"
            "});\n"
        )
        self.assertEqual(self.rule.check([_file(text, relpath="notes.txt")]), [])

    def test_python_extension_out_of_scope(self):
        # The dataset/messaging shapes are JS/TS-only concepts; a .py file
        # with lookalike text should never match this rule's file filter.
        text = (
            "def addEventListener(kind, handler):\n"
            "    taskId = button.dataset.taskId\n"
            "    chrome.runtime.sendMessage({'taskId': taskId})\n"
        )
        self.assertEqual(self.rule.check([_file(text, relpath="content.py")]), [])


if __name__ == "__main__":
    unittest.main()
