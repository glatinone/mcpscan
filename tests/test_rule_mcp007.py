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
