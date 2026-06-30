"""Filesystem discovery: walk a target and classify files for the rules."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, List

# Directories we never want to descend into.
IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", ".idea", ".tox",
}

# Don't try to read anything larger than this (bytes) — likely a binary/blob.
MAX_FILE_BYTES = 2_000_000

SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx", ".sh", ".bash"}
CONFIG_EXTS = {".json", ".toml", ".yaml", ".yml"}

# File/Dir names that mark MCP or Claude Code supply-chain surface.
MANIFEST_NAMES = {
    "package.json", "mcp.json", "claude_desktop_config.json",
    "pyproject.toml", "requirements.txt", "smithery.yaml", "mcp.yaml",
}


@dataclass
class FileInfo:
    relpath: str            # path relative to scan root (posix-style)
    abspath: str
    text: str
    kind: str               # "source" | "config" | "manifest" | "other"
    in_dot_claude: bool     # lives under a .claude/ directory

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    _lines: List[str] = field(default=None, repr=False, compare=False)

    @property
    def ext(self) -> str:
        return os.path.splitext(self.relpath)[1].lower()

    @property
    def name(self) -> str:
        return os.path.basename(self.relpath)


def _classify(name: str, ext: str) -> str:
    if name in MANIFEST_NAMES:
        return "manifest"
    if ext in SOURCE_EXTS:
        return "source"
    if ext in CONFIG_EXTS:
        return "config"
    return "other"


def discover_files(root: str) -> List[FileInfo]:
    """Walk *root*, returning readable text files we care about."""
    root = os.path.abspath(root)
    out: List[FileInfo] = []

    if os.path.isfile(root):
        info = _load(root, os.path.dirname(root))
        return [info] if info else []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            info = _load(full, root)
            if info:
                out.append(info)
    return out


def _load(full: str, root: str) -> "FileInfo | None":
    name = os.path.basename(full)
    ext = os.path.splitext(name)[1].lower()
    kind = _classify(name, ext)
    if kind == "other":
        return None
    try:
        if os.path.getsize(full) > MAX_FILE_BYTES:
            return None
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None

    rel = os.path.relpath(full, root).replace(os.sep, "/")
    in_claude = ".claude/" in ("/" + rel + "/")
    return FileInfo(relpath=rel, abspath=full, text=text, kind=kind, in_dot_claude=in_claude)


def by_kind(files: Iterable[FileInfo], *kinds: str) -> List[FileInfo]:
    wanted = set(kinds)
    return [f for f in files if f.kind in wanted]
