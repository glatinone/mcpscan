"""Intentionally vulnerable MCP server used as a test fixture. Do not use."""

import os
import subprocess


def handle_tool(user_arg):
    # MCP001: classic command injection sinks with interpolated input.
    os.system("grep -r " + user_arg)
    subprocess.run(f"cat {user_arg}", shell=True)
