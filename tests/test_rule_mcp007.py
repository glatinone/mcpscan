"""Tests for MCP007 (path traversal), mcpscan/rules/path_traversal.py.

Regression coverage for CVE-2026-27825 (sooperset/mcp-atlassian <= 0.16.0):
download_attachment(url, target_path) wrote to `target_path`, a bare tool
parameter, with no base-directory check. The line-based check missed it because
nothing on the `open(...)` line was interpolated. v0.17.0 fixed it with
validate_safe_path(). Also covers a false positive from the same repo: browser
`window.open(` inside a Python HTML string.
"""

import unittest

from mcpscan.findings import Severity
from mcpscan.loaders import FileInfo
from mcpscan.rules.path_traversal import PathTraversal

VULNERABLE = '''
import os

def download_attachment(self, url, target_path):
    if not os.path.isabs(target_path):
        target_path = os.path.abspath(target_path)
    with open(target_path, "wb") as f:
        f.write(b"x")
'''

FIXED = '''
import os
from .io import validate_safe_path

def download_attachment(self, url, target_path):
    if not os.path.isabs(target_path):
        target_path = os.path.abspath(target_path)
    validate_safe_path(target_path)
    with open(target_path, "wb") as f:
        f.write(b"x")
'''


def _file(text, relpath="server.py"):
    return FileInfo(
        relpath=relpath, abspath=relpath, text=text, kind="source", in_dot_claude=False
    )


def _check(text):
    return PathTraversal().check([_file(text)])


class TestParamWriteSink(unittest.TestCase):
    def test_cve_2026_27825_shape_is_flagged(self):
        findings = _check(VULNERABLE)
        self.assertEqual([f.line for f in findings], [7])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_validate_safe_path_fix_is_clean(self):
        self.assertEqual(_check(FIXED), [])

    def test_resolve_plus_prefix_check_is_clean(self):
        self.assertEqual(_check(
            "from pathlib import Path\n"
            "def save(p, data):\n"
            "    q = Path(p).resolve()\n"
            "    if not q.is_relative_to(BASE):\n"
            "        raise ValueError(p)\n"
            "    q.write_bytes(data)\n"
        ), [])

    def test_path_derived_write_text_and_shutil_are_flagged(self):
        findings = _check(
            "import shutil\nfrom pathlib import Path\n"
            "def save(dest, src):\n"
            "    out = Path(dest)\n"
            "    out.write_text('x')\n"
            "    shutil.copy(src, dest)\n"
        )
        self.assertEqual([f.line for f in findings], [5, 6])

    def test_read_mode_and_mkdir_are_not_write_sinks(self):
        self.assertEqual(_check(
            "from pathlib import Path\n"
            "def load(p):\n"
            "    Path(p).mkdir(parents=True)\n"
            "    return open(p, 'rb').read()\n"
        ), [])

    def test_non_parameter_path_is_not_flagged(self):
        self.assertEqual(_check(
            "def save(data):\n"
            "    with open('out.json', 'w') as f:\n"
            "        f.write(data)\n"
        ), [])


class TestJoinedAndArgumentPaths(unittest.TestCase):
    """CVE-2026-44336 (PraisonAI rules_create), CVE-2026-84201 (appium-mcp-server write_file /
    write_files_batch), CVE-2026-40576 (excel-mcp-server get_excel_path)."""

    def test_join_then_open_write_is_flagged(self):
        findings = _check(
            "import os\n"
            "def rules_create(rule_name, content):\n"
            "    rule_path = os.path.join(RULES_DIR, rule_name)\n"
            "    with open(rule_path, 'w') as f:\n"
            "        f.write(content)\n"
        )
        self.assertEqual([f.line for f in findings], [4])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_join_with_commonpath_check_is_clean(self):
        self.assertEqual(_check(
            "import os\n"
            "def rules_create(rule_name, content):\n"
            "    rule_path = os.path.realpath(os.path.join(RULES_DIR, rule_name))\n"
            "    if os.path.commonpath([RULES_DIR, rule_path]) != RULES_DIR:\n"
            "        raise ValueError(rule_name)\n"
            "    with open(rule_path, 'w') as f:\n"
            "        f.write(content)\n"
        ), [])

    def test_arguments_get_and_batch_loop_are_flagged(self):
        findings = _check(
            "async def handle_call_tool(name, arguments):\n"
            "    path = arguments.get('path')\n"
            "    target = PROJECT_ROOT / path\n"
            "    with open(target, 'w') as f:\n"
            "        f.write(arguments['content'])\n"
            "async def write_batch(arguments):\n"
            "    for file in arguments.get('files', []):\n"
            "        (PROJECT_ROOT / file['path']).write_text(file['content'])\n"
        )
        self.assertEqual([f.line for f in findings], [4, 8])

    def test_arguments_get_with_resolve_check_is_clean(self):
        self.assertEqual(_check(
            "async def handle_call_tool(name, arguments):\n"
            "    target = (PROJECT_ROOT / arguments['path']).resolve()\n"
            "    if not target.is_relative_to(PROJECT_ROOT):\n"
            "        raise ValueError('outside project')\n"
            "    target.write_text(arguments['content'])\n"
        ), [])

    def test_path_builder_helper_is_flagged(self):
        findings = _check(
            "import os\n"
            "def get_excel_path(filename):\n"
            "    if os.path.isabs(filename):\n"
            "        return filename\n"
            "    return os.path.join(EXCEL_FILES_PATH, filename)\n"
        )
        self.assertEqual([f.line for f in findings], [5])
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_path_builder_with_containment_check_is_clean(self):
        self.assertEqual(_check(
            "import os\n"
            "def get_excel_path(filename):\n"
            "    base = os.path.realpath(EXCEL_FILES_PATH)\n"
            "    p = os.path.realpath(os.path.join(base, filename))\n"
            "    if os.path.commonpath([base, p]) != base:\n"
            "        raise ValueError(filename)\n"
            "    return p\n"
        ), [])

    def test_save_of_joined_path_is_flagged_but_not_a_handed_in_path(self):
        findings = _check(
            "import os\n"
            "def export(wb, name):\n"
            "    wb.save(os.path.join(OUT_DIR, name))\n"
            "def write_data(filepath, wb):\n"
            "    wb.save(filepath)\n"
        )
        self.assertEqual([f.line for f in findings], [3])

    def test_pytest_tmp_path_is_not_caller_input(self):
        self.assertEqual(_check(
            "def test_upload(tmp_path):\n"
            "    (tmp_path / 'a.txt').write_text('x')\n"
        ), [])


class TestWindowOpenFalsePositive(unittest.TestCase):
    def test_js_window_open_in_python_string_is_not_flagged(self):
        self.assertEqual(_check(
            'html = f"""<script>window.open(\'\', \'_self\').close(); {status}</script>"""\n'
        ), [])

    def test_interpolated_open_is_still_flagged(self):
        findings = _check('open("data/" + name).read()\n')  # mcpscan: ignore[MCP007]
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
