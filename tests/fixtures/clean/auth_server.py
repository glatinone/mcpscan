"""A hardened MCP server authorization fixture — mcpscan should report nothing here."""

import urllib.parse
import urllib.request

import jwt


def www_authenticate(error=None):
    challenge = f'Bearer resource_metadata="{PRM_URL}"'
    return challenge + (f', error="{error}"' if error else "")


def call_downstream(path):
    req = urllib.request.Request(DOWNSTREAM + path)
    # The server's own credential, never the client's token.
    req.add_header("Authorization", f"Bearer {SERVICE_TOKEN}")
    return req


def authenticate(handler, method):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
    if "access_token" in q:
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", www_authenticate("invalid_request"))
        return None
    h = handler.headers.get("Authorization", "")
    claims = jwt.decode(h[7:], KEY, algorithms=["RS256"], audience=RESOURCE, issuer=ISSUER)
    if method == "tools/call" and "notes:read" not in claims.get("scope", "").split():
        handler.send_response(403)
        return None
    return claims


def do_GET(handler):
    if handler.path == "/.well-known/oauth-protected-resource":
        return {"resource": RESOURCE, "authorization_servers": [ISSUER]}
    return None
