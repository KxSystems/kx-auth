"""`kx auth introspect` end to end through the argparse entry point.

The required regression: a valid token exits 0, a bad/expired/forbidden token exits non-0 (the
specific codes), and `--json` emits the structured envelope an agent branches on. Invoked in-process
via `cli.main`, asserting the `SystemExit` code; the pub key is written to `tmp_path`.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kx_auth_cli import cli

# Must match the values the `mint` fixture encodes (conftest.py).
ISSUER = "https://issuer.test"
AUDIENCE = "kx-mcp"
KID = "test-key-1"  # must match conftest.KID, which `mint` puts in every token's header


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    return code if isinstance(code, int) else 1


@pytest.fixture
def pub_path(keypair, tmp_path):
    _, pub = keypair
    p = tmp_path / "public.pem"
    p.write_text(pub)
    return str(p)


@pytest.fixture
def jwks_uri(keypair):
    """An in-process JWKS endpoint serving the session `keypair`'s public half, keyed under
    conftest.KID — the same JWKS fetch shape `introspect --jwks-uri` hits (verified: a bare
    synchronous `httpx.get`, no caching), just served locally instead of by a real IdP."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from jwt.algorithms import RSAAlgorithm

    _, pub_pem = keypair
    public_key = load_pem_public_key(pub_pem.encode())
    jwk = RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(public_key, as_dict=True)
    jwk["kid"] = KID
    body = json.dumps({"keys": [jwk]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/jwks.json"
    finally:
        httpd.shutdown()


def _args(token: str, pub_path: str, *extra: str) -> list[str]:
    return [
        "auth", "introspect", token,
        "--public-key-path", pub_path,
        "--issuer", ISSUER, "--audience", AUDIENCE,
        *extra,
    ]


def test_valid_token_exits_0(mint, pub_path):
    assert _run(_args(mint(), pub_path)) == 0


def test_expired_token_exits_3(mint, pub_path):
    assert _run(_args(mint(exp_delta=-10), pub_path)) == 3


def test_wrong_audience_exits_4(mint, pub_path):
    assert _run(_args(mint(aud="other"), pub_path)) == 4


def test_bad_signature_exits_1(mint, pub_path, other_priv):
    assert _run(_args(mint(priv=other_priv), pub_path)) == 1


def test_no_token_is_usage_error_2(pub_path, monkeypatch):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    assert _run(["auth", "introspect", "--public-key-path", pub_path]) == 2


def test_token_from_env(mint, pub_path, monkeypatch):
    monkeypatch.setenv("KX_AUTH_TOKEN", mint())
    assert _run(["auth", "introspect", "--public-key-path", pub_path,
                 "--issuer", ISSUER, "--audience", AUDIENCE]) == 0


def test_json_envelope_on_valid(mint, pub_path, capsys):
    assert _run(_args(mint(), pub_path, "--json")) == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "ok" and envelope["result"]["valid"] is True
    assert envelope["result"]["client_id"] == "alice"
    assert envelope["result"]["claims"]["iss"] == ISSUER


def test_json_envelope_on_failure_has_reason(mint, pub_path, capsys):
    assert _run(_args(mint(exp_delta=-10), pub_path, "--json")) == 3
    envelope = json.loads(capsys.readouterr().out)
    # A failure carries no `result` (and so no `valid`): the status already says the token did not validate.
    assert envelope["status"] == "auth_required" and "result" not in envelope
    assert "reason" in envelope


# --- token precedence: argument > piped stdin > ambient env ------------------------------------


def test_piped_token_outranks_an_ambient_env_token(mint, pub_path, monkeypatch, piped_stdin, capsys):
    """`introspect` is the pre-flight, so validating the WRONG token is the worst failure it has.

    With the environment outranking stdin, `echo $TOKEN | kx auth introspect` reported a verdict about
    whatever $KX_AUTH_TOKEN happened to hold — convincingly, and about a question nobody asked. Pinned
    by using an *expired* env token and a valid piped one: the wrong precedence exits 3, not 0.
    """
    monkeypatch.setenv("KX_AUTH_TOKEN", mint(exp_delta=-10))  # stale, would exit 3
    piped_stdin(mint() + "\n")  # valid, should win → exit 0

    assert _run(["auth", "introspect", "--public-key-path", str(pub_path),
                 "--issuer", ISSUER, "--audience", AUDIENCE]) == 0
    assert "KX_AUTH_TOKEN" in capsys.readouterr().err


def test_argument_token_outranks_both(mint, pub_path, monkeypatch, piped_stdin):
    """The positional is the most explicit source, so it beats a pipe and the environment alike."""
    monkeypatch.setenv("KX_AUTH_TOKEN", mint(exp_delta=-10))
    piped_stdin(mint(aud="wrong-audience"))

    assert _run(_args(mint(), pub_path)) == 0


def test_env_token_is_still_used_when_nothing_is_piped(mint, pub_path, monkeypatch, piped_stdin):
    """The reordering must not cost the env path: an empty pipe falls through to $KX_AUTH_TOKEN."""
    monkeypatch.setenv("KX_AUTH_TOKEN", mint())
    piped_stdin("  \n")

    assert _run(["auth", "introspect", "--public-key-path", str(pub_path),
                 "--issuer", ISSUER, "--audience", AUDIENCE]) == 0


def test_no_command_shows_help_exits_2():
    assert _run(["auth"]) == 2


# --- KX_MCP_AUTH*-only config: no flags at all, matching the container's own posture -----------


@pytest.fixture(autouse=True)
def _no_stray_kx_mcp_auth_env(monkeypatch):
    for name in (
        "KX_MCP_AUTH", "KX_MCP_AUTH_PUBLIC_KEY_PATH", "KX_MCP_AUTH_PUBLIC_KEY",
        "KX_MCP_AUTH_JWKS_URI", "KX_MCP_AUTH_ISSUER", "KX_MCP_AUTH_AUDIENCE",
        "KX_MCP_AUTH_ALGORITHM", "KX_MCP_AUTH_REQUIRED_SCOPES",
    ):
        monkeypatch.delenv(name, raising=False)


def test_env_only_config_validates_with_no_flags(mint, pub_path, monkeypatch):
    monkeypatch.setenv("KX_MCP_AUTH", "static")
    monkeypatch.setenv("KX_MCP_AUTH_PUBLIC_KEY_PATH", pub_path)
    monkeypatch.setenv("KX_MCP_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("KX_MCP_AUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("KX_MCP_AUTH_REQUIRED_SCOPES", "kdbx.read")

    assert _run(["auth", "introspect", mint(scope="kdbx.read")]) == 0


def test_env_only_config_is_actually_consulted_not_a_vacuous_pass(mint, pub_path, monkeypatch):
    """The negative that proves the positive above isn't passing by default: change only the env,
    no flags, and the wrong audience must still be caught."""
    monkeypatch.setenv("KX_MCP_AUTH", "static")
    monkeypatch.setenv("KX_MCP_AUTH_PUBLIC_KEY_PATH", pub_path)
    monkeypatch.setenv("KX_MCP_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("KX_MCP_AUTH_AUDIENCE", "some-other-audience")

    assert _run(["auth", "introspect", mint()]) == 4


def test_explicit_flag_overrides_the_matching_env_var(mint, pub_path, monkeypatch):
    monkeypatch.setenv("KX_MCP_AUTH", "static")
    monkeypatch.setenv("KX_MCP_AUTH_PUBLIC_KEY_PATH", pub_path)
    monkeypatch.setenv("KX_MCP_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("KX_MCP_AUTH_AUDIENCE", "some-other-audience")  # would fail if not overridden

    assert _run(_args(mint(), pub_path)) == 0


# --- --jwks-uri: the remote-endpoint verification mode ------------------------------------------


def test_jwks_uri_mode_validates_against_a_live_endpoint(mint, jwks_uri):
    assert _run(["auth", "introspect", mint(), "--jwks-uri", jwks_uri,
                 "--issuer", ISSUER, "--audience", AUDIENCE]) == 0


# --- --public-key (inline), --algorithm, --required-scopes: composed in one realistic call ------


@pytest.mark.parametrize("required_scope, expected_code", [("kdbx.read", 0), ("kdbx.write", 4)])
def test_public_key_inline_with_algorithm_and_required_scopes(mint, keypair, required_scope, expected_code):
    _, pub = keypair
    code = _run([
        "auth", "introspect", mint(scope="kdbx.read"),
        "--public-key", pub, "--algorithm", "RS256",
        "--issuer", ISSUER, "--audience", AUDIENCE,
        "--required-scopes", required_scope,
    ])
    assert code == expected_code


# Regression for finding kx-auth-cli #5 — a missing token prints bare text and emits no JSON envelope.
def test_an_introspect_usage_refusal_still_emits_an_envelope_under_json(
    monkeypatch, piped_stdin, json_envelope
):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    piped_stdin("")
    code, envelope = json_envelope(["auth", "introspect", "--json"])
    assert code == 2, f"an introspect usage refusal must stay exit 2, got {code}"
    assert envelope["status"] == "error", envelope


# --- the envelope shape: {status, result} on success, {status, reason} on failure ------------------


def test_success_nests_the_verdict_under_result(mint, pub_path, capsys):
    assert _run(_args(mint(), pub_path, "--json")) == 0
    env = json.loads(capsys.readouterr().out)
    assert set(env) == {"status", "result"}
    assert set(env["result"]) == {"valid", "client_id", "scopes", "claims"}


def test_failures_are_status_and_reason_only(mint, pub_path, monkeypatch, piped_stdin, capsys):
    assert _run(_args(mint(exp_delta=-10), pub_path, "--json")) == 3
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    piped_stdin("")
    assert _run(["auth", "introspect", "--public-key-path", pub_path, "--json"]) == 2
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}
