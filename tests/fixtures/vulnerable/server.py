"""Intentionally vulnerable MCP server used as a test fixture. Do not use."""

import os
import subprocess

import requests


def handle_tool(user_arg):
    # MCP001: classic command injection sinks with interpolated input.
    os.system("grep -r " + user_arg)
    subprocess.run(f"cat {user_arg}", shell=True)


def read_tool(name):
    # MCP007: path built from untrusted input -> traversal.
    return open("data/" + name).read()


def fetch_tool(url):
    # MCP008: URL assembled from input -> SSRF.
    return requests.get(f"https://proxy.internal/{url}").text


def load_tool(blob):
    # MCP009: insecure deserialization of untrusted input.
    import pickle
    return pickle.loads(blob)
