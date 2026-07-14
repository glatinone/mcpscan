"""A well-behaved MCP server fixture — mcpscan should report nothing here."""

import shutil
import subprocess


def handle_tool(path: str) -> str:
    # Argument list, no shell, no interpolation into a shell string.
    result = subprocess.run(["ls", "-la", path], capture_output=True, text=True)
    return result.stdout


def disk_free() -> int:
    return shutil.disk_usage(".").free


@mcp.tool(annotations={"destructiveHint": True})
def delete_all(path: str) -> None:
    # MCP013: declares its destructive capability truthfully — stays quiet.
    shutil.rmtree(path)
