"""Tests for MCP024-MCP030 (server-side MCP authorization rules).

Every rule gets at least one positive and one negative case. The positive
cases mirror the deliberately naive server from the scanner-vs-auth
experiment; the negative cases mirror its hardened twin.
"""

import unittest

from mcpscan.loaders import FileInfo
from mcpscan.rules.server_auth import (
    AccessTokenFromQueryString,
    JwtAudienceNotValidated,
    JwtIssuerNotValidated,
    JwtSignatureDisabled,
    NoProtectedResourceMetadata,
    TokenPassthrough,
    UnauthorizedWithoutResourceMetadata,
)


def _file(text: str, relpath: str = "server.py") -> FileInfo:
    return FileInfo(relpath=relpath, abspath="x", text=text, kind="source", in_dot_claude=False)


# Marks a file as an MCP server (JSON-RPC dispatch) for the scope gate.
MCP_HEAD = (
    "import jwt\n"
    "def dispatch(method):\n"
    "    if method == 'tools/call':\n"
    "        pass\n"
)

GOOD_DECODE = (
    "claims = jwt.decode(token, key, algorithms=['RS256'],\n"
    "                    audience=RESOURCE, issuer=ISSUER)\n"
)


def _ids(findings):
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------
# Scope gate
# --------------------------------------------------------------------------

class TestScopeGate(unittest.TestCase):
    def test_non_mcp_file_is_out_of_scope(self):
        text = "import jwt\nclaims = jwt.decode(t, k, algorithms=['HS256'])\n"
        for rule in (JwtAudienceNotValidated(), JwtIssuerNotValidated()):
            self.assertEqual(rule.check([_file(text, "app.py")]), [])

    def test_mcp_sdk_import_is_in_scope(self):
        text = ("from mcp.server.fastmcp import FastMCP\nimport jwt\n"
                "claims = jwt.decode(t, k, algorithms=['RS256'], issuer=I)\n")
        self.assertEqual(len(JwtAudienceNotValidated().check([_file(text)])), 1)

    def test_split_out_auth_module_is_in_scope_when_project_has_a_server(self):
        server = _file(MCP_HEAD, "server.py")
        auth = _file(
            "import jwt\n"
            "def authenticate(request):\n"
            "    token = request.headers.get('Authorization', '')[7:]\n"
            "    return jwt.decode(token, KEY, algorithms=['RS256'], issuer=I)\n",
            "auth.py")
        findings = JwtAudienceNotValidated().check([server, auth])
        self.assertEqual([f.path for f in findings], ["auth.py"])

    def test_test_files_are_out_of_scope(self):
        text = MCP_HEAD + "claims = jwt.decode(t, k, algorithms=['RS256'])\n"
        for path in ("tests/helpers.py", "test_server.py", "conftest.py"):
            self.assertEqual(JwtAudienceNotValidated().check([_file(text, path)]), [])

    def test_authlib_jwt_is_not_mistaken_for_pyjwt(self):
        text = ("from authlib.jose import jwt\n" + MCP_HEAD.replace("import jwt\n", "")
                + "claims = jwt.decode(t, k)\n")
        self.assertEqual(JwtAudienceNotValidated().check([_file(text)]), [])

    def test_unparseable_file_is_skipped(self):
        self.assertEqual(JwtAudienceNotValidated().check([_file(MCP_HEAD + "def (:\n")]), [])


# --------------------------------------------------------------------------
# MCP024 signature disabled
# --------------------------------------------------------------------------

class TestJwtSignatureDisabled(unittest.TestCase):
    rule = JwtSignatureDisabled()

    def test_verify_signature_false_fires(self):
        text = MCP_HEAD + "c = jwt.decode(t, options={'verify_signature': False})\n"
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP024")
        self.assertEqual(findings[0].line, 5)

    def test_alg_none_fires(self):
        text = MCP_HEAD + "c = jwt.decode(t, k, algorithms=['RS256', 'none'], audience=A, issuer=I)\n"
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_legacy_verify_false_fires(self):
        text = MCP_HEAD + "c = jwt.decode(t, k, verify=False)\n"  # mcpscan: ignore[MCP010]
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_jose_alias_fires(self):
        text = (MCP_HEAD.replace("import jwt", "from jose import jwt as jose_jwt")
                + "c = jose_jwt.decode(t, k, options={'verify_signature': False})\n")
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_verified_decode_is_clean(self):
        self.assertEqual(self.rule.check([_file(MCP_HEAD + GOOD_DECODE)]), [])

    def test_disabled_signature_is_not_also_reported_as_aud_or_iss(self):
        text = MCP_HEAD + "c = jwt.decode(t, options={'verify_signature': False})\n"
        self.assertEqual(JwtAudienceNotValidated().check([_file(text)]), [])
        self.assertEqual(JwtIssuerNotValidated().check([_file(text)]), [])


# --------------------------------------------------------------------------
# MCP025 audience / MCP026 issuer
# --------------------------------------------------------------------------

class TestJwtAudienceAndIssuer(unittest.TestCase):
    def test_verify_aud_false_fires_mcp025(self):
        text = MCP_HEAD + (
            "c = jwt.decode(t, k, algorithms=['RS256'],\n"
            "               options={'verify_aud': False}, issuer=I)\n")
        findings = JwtAudienceNotValidated().check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP025")
        self.assertIn("verify_aud", findings[0].detail)

    def test_missing_audience_fires_mcp025(self):
        text = MCP_HEAD + "c = jwt.decode(t, k, algorithms=['RS256'], issuer=I)\n"
        self.assertEqual(len(JwtAudienceNotValidated().check([_file(text)])), 1)

    def test_from_jwt_import_decode_fires(self):
        text = (MCP_HEAD.replace("import jwt", "from jwt import decode")
                + "c = decode(t, k, algorithms=['RS256'])\n")
        self.assertEqual(_ids(JwtAudienceNotValidated().check([_file(text)])
                              + JwtIssuerNotValidated().check([_file(text)])),
                         ["MCP025", "MCP026"])

    def test_missing_issuer_fires_mcp026(self):
        text = MCP_HEAD + "c = jwt.decode(t, k, algorithms=['RS256'], audience=A)\n"
        findings = JwtIssuerNotValidated().check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP026")

    def test_verify_iss_false_fires_mcp026(self):
        text = MCP_HEAD + ("c = jwt.decode(t, k, algorithms=['RS256'], audience=A, "
                           "issuer=I, options={'verify_iss': False})\n")
        self.assertEqual(len(JwtIssuerNotValidated().check([_file(text)])), 1)

    def test_full_validation_is_clean(self):
        f = _file(MCP_HEAD + GOOD_DECODE)
        self.assertEqual(JwtAudienceNotValidated().check([f]), [])
        self.assertEqual(JwtIssuerNotValidated().check([f]), [])

    def test_session_cookie_decode_is_out_of_scope(self):
        text = MCP_HEAD + ("token_cookie = request.cookies.get('token')\n"
                           "c = jwt.decode(token_cookie, K, algorithms=['HS256'])\n")
        self.assertEqual(JwtAudienceNotValidated().check([_file(text)]), [])

    def test_star_kwargs_is_not_guessed(self):
        text = MCP_HEAD + "c = jwt.decode(t, k, **DECODE_KW)\n"
        self.assertEqual(JwtAudienceNotValidated().check([_file(text)]), [])
        self.assertEqual(JwtIssuerNotValidated().check([_file(text)]), [])


# --------------------------------------------------------------------------
# MCP027 / MCP028 discovery
# --------------------------------------------------------------------------

NAIVE_401 = MCP_HEAD + (
    "def authenticate(handler):\n"
    "    h = handler.headers.get('Authorization', '')\n"
    "    if not h:\n"
    "        handler.send_response(401)\n"
)

CHALLENGE = (
    "def challenge(prm_url):\n"
    "    return f'Bearer resource_metadata=\"{prm_url}\"'\n"
)

PRM_ROUTE = (
    "def do_GET(self):\n"
    "    if self.path == '/.well-known/oauth-protected-resource':\n"
    "        return self._send(200, {'resource': RESOURCE})\n"
)


class TestDiscovery(unittest.TestCase):
    def test_bare_401_fires_both(self):
        f = _file(NAIVE_401)
        a = UnauthorizedWithoutResourceMetadata().check([f])
        b = NoProtectedResourceMetadata().check([f])
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].line, 8)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0].rule_id, "MCP028")

    def test_raise_and_return_tuple_shapes_count_as_401(self):
        for body in ("    raise AuthError(401)\n", "    return {'error': 'no'}, 401\n",
                     "    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)\n"):
            text = NAIVE_401.replace("        handler.send_response(401)\n", "    " + body)
            self.assertEqual(len(UnauthorizedWithoutResourceMetadata().check([_file(text)])), 1, body)

    def test_comparing_against_401_is_not_a_401_response(self):
        text = NAIVE_401.replace("handler.send_response(401)", "assert r.status == 401")
        self.assertEqual(UnauthorizedWithoutResourceMetadata().check([_file(text)]), [])

    def test_challenge_and_prm_route_are_clean(self):
        f = _file(NAIVE_401 + CHALLENGE + PRM_ROUTE)
        self.assertEqual(UnauthorizedWithoutResourceMetadata().check([f]), [])
        self.assertEqual(NoProtectedResourceMetadata().check([f]), [])

    def test_challenge_in_another_file_counts(self):
        files = [_file(NAIVE_401), _file(CHALLENGE + PRM_ROUTE, "discovery.py")]
        self.assertEqual(UnauthorizedWithoutResourceMetadata().check(files), [])
        self.assertEqual(NoProtectedResourceMetadata().check(files), [])

    def test_prm_route_only_downgrades_mcp027_to_low(self):
        findings = UnauthorizedWithoutResourceMetadata().check([_file(NAIVE_401 + PRM_ROUTE)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.label, "low")

    def test_prm_url_that_is_built_but_never_routed_does_not_count(self):
        text = NAIVE_401 + (
            "def prm_url(port):\n"
            "    return f'http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp'\n")
        self.assertEqual(len(NoProtectedResourceMetadata().check([_file(text)])), 1)

    def test_decorator_route_and_sdk_helper_count_as_prm(self):
        for extra in ("@app.get('/.well-known/oauth-protected-resource')\ndef prm():\n    pass\n",
                      "from mcp.server.auth.routes import create_protected_resource_routes\n"):
            self.assertEqual(NoProtectedResourceMetadata().check([_file(NAIVE_401 + extra)]), [])

    def test_a_test_asserting_on_the_header_does_not_hide_the_bug(self):
        test = _file("assert 'resource_metadata=' in r.headers['WWW-Authenticate']\n",
                     "tests/test_auth.py")
        self.assertEqual(len(UnauthorizedWithoutResourceMetadata().check([_file(NAIVE_401), test])), 1)

    def test_server_without_bearer_handling_is_out_of_scope(self):
        text = "def dispatch(method):\n    if method == 'tools/list':\n        return {}, 401\n"
        self.assertEqual(UnauthorizedWithoutResourceMetadata().check([_file(text)]), [])
        self.assertEqual(NoProtectedResourceMetadata().check([_file(text)]), [])


# --------------------------------------------------------------------------
# MCP029 token passthrough
# --------------------------------------------------------------------------

NAIVE_PASSTHROUGH = MCP_HEAD + (
    "def call_downstream(path, authorization):\n"
    "    req = urllib.request.Request(BASE + path)\n"
    "    req.add_header('Authorization', authorization)\n"
    "    return urllib.request.urlopen(req)\n"
    "\n"
    "def authenticate(handler):\n"
    "    h = handler.headers.get('Authorization', '')\n"
    "    token = h[7:]\n"
    "    return claims_for(token), token\n"
    "\n"
    "class Handler:\n"
    "    def do_POST(self):\n"
    "        auth = authenticate\n"
    "        claims, token = auth(self)\n"
    "        ds_auth = f'Bearer {token}'\n"
    "        return call_downstream('/notes', ds_auth)\n"
)


class TestTokenPassthrough(unittest.TestCase):
    rule = TokenPassthrough()

    def test_interprocedural_passthrough_fires(self):
        findings = self.rule.check([_file(NAIVE_PASSTHROUGH)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP029")
        self.assertEqual(findings[0].line, 20)
        self.assertIn("call_downstream", findings[0].detail)

    def test_servers_own_credential_is_clean(self):
        text = NAIVE_PASSTHROUGH.replace("f'Bearer {token}'", "f'Bearer {cfg.downstream_token}'")
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_direct_headers_dict_fires(self):
        text = MCP_HEAD + (
            "def tool(request):\n"
            "    auth = request.headers['Authorization']\n"
            "    return client.get(API, headers={'Authorization': auth})\n")
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 7)

    def test_subscript_assignment_and_method_alias_fire(self):
        text = MCP_HEAD + (
            "class S:\n"
            "    def _bearer(self, request):\n"
            "        return request.headers.get('authorization').split()[1]\n"
            "    def handle(self, request):\n"
            "        hdrs = {}\n"
            "        hdrs['Authorization'] = 'Bearer ' + self._bearer(request)\n"
            "        return hdrs\n")
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_conditional_alias_covers_both_branches(self):
        text = NAIVE_PASSTHROUGH.replace(
            "auth = authenticate", "auth = authenticate if NAIVE else strict_authenticate"
        ) + "def strict_authenticate(handler):\n    return None, None\n"
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_token_used_only_for_validation_is_clean(self):
        text = MCP_HEAD + (
            "def tool(request):\n"
            "    token = request.headers.get('Authorization', '')[7:]\n"
            "    claims = jwt.decode(token, KEY, algorithms=['RS256'], audience=A, issuer=I)\n"
            "    svc = service_token_for(claims['sub'])\n"
            "    return client.get(API, headers={'Authorization': f'Bearer {svc}'})\n")
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_headers_of_an_outbound_request_are_not_a_source(self):
        # Re-using the credential this code itself sent (e.g. polling a job) is fine.
        text = MCP_HEAD + (
            "def poll(raw_response):\n"
            "    return {'Authorization': raw_response.request.headers.get('Authorization', '')}\n")
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_non_mcp_proxy_is_out_of_scope(self):
        text = ("def proxy(request):\n"
                "    return client.get(API, headers={'Authorization': request.headers['Authorization']})\n")
        self.assertEqual(self.rule.check([_file(text, "gateway.py")]), [])


# --------------------------------------------------------------------------
# MCP030 token from the query string
# --------------------------------------------------------------------------

class TestAccessTokenFromQueryString(unittest.TestCase):
    rule = AccessTokenFromQueryString()

    def test_parse_qs_get_fires(self):
        text = MCP_HEAD + (
            "q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)\n"
            "token = (q.get('access_token') or [None])[0]\n")
        findings = self.rule.check([_file(text)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "MCP030")
        self.assertEqual(findings[0].line, 6)

    def test_framework_query_objects_fire(self):
        for expr in ("request.args.get('access_token')",
                     "request.query_params['access_token']",
                     "request.GET.get('access_token')"):
            self.assertEqual(len(self.rule.check([_file(MCP_HEAD + f"t = {expr}\n")])), 1, expr)

    def test_fastapi_query_param_fires(self):
        text = MCP_HEAD + "async def mcp(access_token: str = Query(None)):\n    pass\n"
        self.assertEqual(len(self.rule.check([_file(text)])), 1)

    def test_rejecting_query_token_is_clean(self):
        text = MCP_HEAD + (
            "q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)\n"
            "if 'access_token' in q:\n"
            "    raise AuthError(401)\n")
        self.assertEqual(self.rule.check([_file(text)]), [])

    def test_token_endpoint_json_response_is_clean(self):
        # An OAuth *client* reading its token response is not a query-string read.
        text = MCP_HEAD + "tok = resp.json()['access_token']\nalt = body.get('access_token')\n"
        self.assertEqual(self.rule.check([_file(text)]), [])


if __name__ == "__main__":
    unittest.main()
