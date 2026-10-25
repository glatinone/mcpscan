"""Intentionally naive MCP server authorization. Test fixture. Do not use."""

import urllib.parse
import urllib.request

import jwt


def call_downstream(path, authorization):
    req = urllib.request.Request(DOWNSTREAM + path)
    req.add_header("Authorization", authorization)
    return req


def authenticate(handler, method):
    if method == "tools/list":
        return None, None
    h = handler.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        token = h[7:]
    else:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
        # MCP030: access token accepted from the query string.
        token = (q.get("access_token") or [None])[0]
    if not token:
        # MCP027 + MCP028: bare 401, no challenge, no PRM endpoint anywhere.
        handler.send_response(401)
        return None, None
    # MCP025 + MCP026: audience check disabled, no issuer.
    claims = jwt.decode(token, KEY, algorithms=["RS256"], options={"verify_aud": False})
    return claims, token


def peek(token):
    # MCP024: signature verification disabled.
    return jwt.decode(token, options={"verify_signature": False})


def handle_tool_call(handler):
    claims, token = authenticate(handler, "tools/call")
    # MCP029: the client's own token is forwarded downstream.
    return call_downstream("/notes", f"Bearer {token}")
