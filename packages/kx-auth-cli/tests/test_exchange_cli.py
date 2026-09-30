"""`kx auth exchange` end to end through the argparse entry point.

The required regression: `exchange` returns an audience-scoped token from a mock STS (exit 0 +
the `--json` envelope). Plus the strategy/exit-code matrix and the `login` → `exchange` cache chain.
The `mock_sts` fixture comes from this suite's `conftest.py`.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest

from kx_auth_cli import cache, cli

_HS256_KEY = "test-secret-key-at-least-32-bytes-long!"


def _jwt(**claims) -> str:
    return jwt.encode(claims, _HS256_KEY, algorithm="HS256")


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    return code if isinstance(code, int) else 1


@pytest.fixture(autouse=True)
def _no_ambient_token(monkeypatch, tmp_path):
    """Keep the environment from leaking a subject token or a real cache into these tests."""
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("KX_AUTH_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("KX_AUTH_CACHE", str(tmp_path / "creds.json"))


# --- the required regression: rfc_8693 → audience-scoped token ---------------------------------


def test_rfc_8693_returns_audience_scoped_token(mock_sts, capsys):
    token_url, captured = mock_sts
    subject = _jwt(sub="alice", aud="mcp")
    code = _run([
        "auth", "exchange", "--subject", subject, "--audience", "kdbai",
        "--token-url", token_url, "--client-id", "mcp-container", "--client-secret", "s3cret",
        "--scope", "kdbx.read", "--json",
    ])
    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "ok"
    assert envelope["result"]["strategy"] == "rfc_8693"
    assert envelope["result"]["claims"]["aud"] == "kdbai"  # the minted token is scoped to the backend
    assert captured[0]["subject_token"] == subject
    assert captured[0]["audience"] == "kdbai"


# --- subject precedence: explicit flag > piped > ambient env > login cache ----------------------


def test_piped_subject_outranks_an_ambient_env_token(mock_sts, monkeypatch, piped_stdin, capsys):
    """The footgun this pins: a stale $KX_AUTH_TOKEN silently shadowing a piped subject.

    `platform token | kx auth exchange` is the documented workload-identity path, and
    $KX_AUTH_TOKEN is very often left over from an earlier `login` or from the exchange→assert
    handoff. While the environment won, the WRONG IDENTITY was exchanged with no error at all.
    """
    token_url, captured = mock_sts
    piped = _jwt(sub="workload", aud="mcp")
    monkeypatch.setenv("KX_AUTH_TOKEN", _jwt(sub="stale-human", aud="mcp"))
    piped_stdin(piped + "\n")

    code = _run([
        "auth", "exchange", "--audience", "kdbx",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s", "--json",
    ])
    assert code == 0
    assert captured[0]["subject_token"] == piped  # not the ambient one


def test_shadowed_env_token_is_reported_on_stderr(mock_sts, monkeypatch, piped_stdin, capsys):
    """Ambiguity is resolved, but never silently — and the note must not pollute --json on stdout."""
    token_url, _ = mock_sts
    piped_stdin(_jwt(sub="workload", aud="mcp"))
    monkeypatch.setenv("KX_AUTH_TOKEN", _jwt(sub="stale-human", aud="mcp"))

    _run([
        "auth", "exchange", "--audience", "kdbx",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s", "--json",
    ])
    out, err = capsys.readouterr()
    assert "KX_AUTH_TOKEN" in err and "ignored" in err
    assert json.loads(out)["status"] == "ok"  # stdout stayed a clean envelope


def test_explicit_subject_outranks_both(mock_sts, monkeypatch, piped_stdin):
    """--subject is the most explicit source, so it wins over a pipe and the environment alike."""
    token_url, captured = mock_sts
    explicit = _jwt(sub="explicit", aud="mcp")
    piped_stdin(_jwt(sub="piped", aud="mcp"))
    monkeypatch.setenv("KX_AUTH_TOKEN", _jwt(sub="ambient", aud="mcp"))

    code = _run([
        "auth", "exchange", "--subject", explicit, "--audience", "kdbx",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s", "--json",
    ])
    assert code == 0
    assert captured[0]["subject_token"] == explicit


def test_env_token_is_still_used_when_nothing_is_piped(mock_sts, monkeypatch, piped_stdin):
    """The reordering must not cost the env path: an empty pipe falls through to $KX_AUTH_TOKEN."""
    token_url, captured = mock_sts
    ambient = _jwt(sub="ambient", aud="mcp")
    monkeypatch.setenv("KX_AUTH_TOKEN", ambient)
    piped_stdin("   \n")  # non-tty but carrying nothing

    code = _run([
        "auth", "exchange", "--audience", "kdbx",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s", "--json",
    ])
    assert code == 0
    assert captured[0]["subject_token"] == ambient


# --- the strategy / exit-code matrix ----------------------------------------------------------


def test_passthrough_audience_mismatch_is_denied_4(capsys):
    subject = _jwt(sub="alice", aud="mcp")
    code = _run([
        "auth", "exchange", "--strategy", "passthrough", "--subject", subject,
        "--audience", "kdbai", "--json",
    ])
    assert code == 4
    assert json.loads(capsys.readouterr().out)["status"] == "denied"


def test_rfc_8693_missing_token_url_is_error_1(capsys):
    subject = _jwt(sub="alice", aud="mcp")
    code = _run(["auth", "exchange", "--subject", subject, "--audience", "kdbai", "--json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_service_account_needs_no_subject_0(mock_sts):
    token_url, captured = mock_sts
    code = _run([
        "auth", "exchange", "--strategy", "service_account", "--audience", "backend-api",
        "--token-url", token_url, "--client-id", "mcp-container", "--client-secret", "s3cret",
    ])
    assert code == 0
    assert "subject_token" not in captured[0]


def test_missing_subject_for_rfc_8693_is_usage_2():
    # no --subject, no $KX_AUTH_TOKEN, stdin empty under pytest → usage error before any network call
    assert _run(["auth", "exchange", "--audience", "kdbai", "--token-url", "http://x/token"]) == 2


# --- the login -> exchange cache chain --------------------------------------------------------


def test_subject_falls_back_to_login_cache(mock_sts, capsys):
    token_url, captured = mock_sts
    server = "https://mcp.example"
    cached_token = _jwt(sub="alice", aud="mcp")
    cache.save(server, {"access_token": cached_token, "token_type": "Bearer"})

    code = _run([
        "auth", "exchange", "--server", server, "--audience", "kdbai",
        "--token-url", token_url, "--json",
    ])
    assert code == 0
    # the cached login token was used as the exchange subject
    assert captured[0]["subject_token"] == cached_token


def test_expired_cache_subject_is_auth_required_3(mock_sts, capsys):
    token_url, captured = mock_sts
    server = "https://mcp.example"
    cache.save(server, {
        "access_token": _jwt(sub="alice", aud="mcp"),
        "expires_at": int(time.time()) - 60,
    })

    code = _run([
        "auth", "exchange", "--server", server, "--audience", "kdbai",
        "--token-url", token_url, "--json",
    ])
    assert code == 3  # auth-required: re-login, not a usage error
    assert json.loads(capsys.readouterr().out)["status"] == "auth_required"
    assert not captured  # the expired token was never sent to the STS


# --- client-secret env fallback ---------------------------------------------------------------


def test_client_secret_falls_back_to_env(mock_sts, monkeypatch):
    token_url, captured = mock_sts
    monkeypatch.setenv("KX_AUTH_CLIENT_SECRET", "env-s3cret")
    code = _run([
        "auth", "exchange", "--strategy", "service_account", "--audience", "backend-api",
        "--token-url", token_url, "--client-id", "mcp-container",
    ])
    assert code == 0
    assert captured[0]["client_secret"] == "env-s3cret"


# --- --client-auth: RFC 6749 §2.3.1's two credential-delivery mechanisms -----------------------


def test_client_auth_basic_moves_credentials_to_the_authorization_header(mock_sts):
    token_url, captured = mock_sts
    code = _run([
        "auth", "exchange", "--strategy", "service_account", "--audience", "backend-api",
        "--token-url", token_url, "--client-id", "mcp-container", "--client-secret", "s3cret",
        "--client-auth", "basic",
    ])
    assert code == 0
    assert "client_id" not in captured[0] and "client_secret" not in captured[0]
    import base64

    scheme, _, encoded = captured[0]["_authorization"].partition(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "mcp-container:s3cret"


def test_client_auth_post_is_the_default_and_keeps_credentials_in_the_form(mock_sts):
    token_url, captured = mock_sts
    code = _run([
        "auth", "exchange", "--strategy", "service_account", "--audience", "backend-api",
        "--token-url", token_url, "--client-id", "mcp-container", "--client-secret", "s3cret",
    ])
    assert code == 0
    assert captured[0]["client_id"] == "mcp-container"
    assert captured[0]["client_secret"] == "s3cret"
    assert captured[0]["_authorization"] == ""


# --- --scope: reaches the actual token request ---------------------------------------------


def test_scope_reaches_the_request(mock_sts):
    token_url, captured = mock_sts
    subject = _jwt(sub="alice", aud="mcp")
    code = _run([
        "auth", "exchange", "--subject", subject, "--audience", "kdbai",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s",
        "--scope", "kdbx.read,kdbx.write", "--scope", "offline_access",
    ])
    assert code == 0
    assert captured[0]["scope"] == "kdbx.read kdbx.write offline_access"


# --- --resource: RFC 8707 -----------------------------------------------------------------------


def test_resource_reaches_the_request(mock_sts):
    token_url, captured = mock_sts
    subject = _jwt(sub="alice", aud="mcp")
    code = _run([
        "auth", "exchange", "--subject", subject, "--resource", "https://backend.example/api",
        "--token-url", token_url, "--client-id", "c", "--client-secret", "s",
    ])
    assert code == 0
    assert captured[0]["resource"] == "https://backend.example/api"


# Regression for finding kx-auth-cli #5 — a missing subject prints bare text and emits no JSON
# envelope.
def test_an_exchange_usage_refusal_still_emits_an_envelope_under_json(
    piped_stdin, json_envelope
):
    piped_stdin("")
    code, envelope = json_envelope(
        ["auth", "exchange", "--audience", "a", "--token-url", "http://x/token", "--json"]
    )
    assert code == 2, f"an exchange usage refusal must stay exit 2, got {code}"
    assert envelope["status"] == "error", envelope


# Regression for finding kx-auth-cli #11 — exchange's human output prints the whole access token.
def test_exchange_human_output_never_prints_the_whole_token(mock_sts, mint, run_cli, capsys):
    token_url, _ = mock_sts
    code = run_cli(
        [
            "auth", "exchange", "--subject", mint(), "--audience", "kdbai",
            "--token-url", token_url, "--client-id", "c", "--client-secret", "s",
        ]
    )
    out, _ = capsys.readouterr()
    assert code == 0, f"the exchange itself failed, so nothing was asserted: {out!r}"
    leaked = [word for word in out.split() if word.count(".") >= 2 and len(word) > 60]
    assert not leaked, f"the human line printed what looks like a whole bearer token: {leaked!r}"


# Regression for finding kx-auth-cli #7 and #2b — a non-numeric cached expires_at reaches an
# unguarded float() in exchange.
@pytest.mark.parametrize("bad", [pytest.param("soon", id="a-string"), pytest.param({"a": 1}, id="a-dict")])
def test_exchange_refuses_a_corrupt_cached_expiry(bad, monkeypatch, json_envelope):
    cache.save("https://mcp.test", {"access_token": "at", "expires_at": bad})
    code, envelope = json_envelope(
        [
            "auth", "exchange", "--server", "https://mcp.test", "--audience", "a",
            "--token-url", "http://127.0.0.1:1/token", "--json",
        ]
    )
    assert code != 0, f"exchange used a credential whose expiry it could not read: {envelope!r}"


# Regression for finding kx-auth-cli #12 — --strategy has no choices=, so a typo is exit 1 rather
# than a usage error.
def test_exchange_rejects_an_unknown_strategy_as_a_usage_error(mock_sts, mint, run_cli, capsys):
    token_url, _ = mock_sts
    code = run_cli(
        [
            "auth", "exchange", "--strategy", "rfc8693", "--subject", mint(),
            "--audience", "a", "--token-url", token_url, "--json",
        ]
    )
    capsys.readouterr()
    assert code == 2, f"a misspelled --strategy is a usage error, expected exit 2, got {code}"


# --- the envelope shape: {status, result} on success, {status, reason} on failure ------------------


def test_success_nests_the_credential_under_result(mock_sts, capsys):
    token_url, _ = mock_sts
    code = _run([
        "auth", "exchange", "--subject", _jwt(sub="alice", aud="mcp"), "--audience", "kdbai",
        "--token-url", token_url, "--client-id", "mcp-container", "--client-secret", "s3cret", "--json",
    ])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert set(env) == {"status", "result"}
    assert set(env["result"]) == {"access_token", "token_type", "expires_in", "strategy", "claims"}


@pytest.mark.parametrize(
    "argv,code",
    [
        pytest.param(["auth", "exchange", "--audience", "a", "--token-url", "http://sts.test/t", "--json"], 2, id="no-subject"),
        pytest.param(["auth", "exchange", "--strategy", "nope", "--subject", "x", "--json"], 2, id="unknown-strategy"),
        pytest.param(["auth", "exchange", "--subject", _jwt(sub="alice", aud="mcp"), "--audience", "a", "--json"], 1, id="missing-token-url"),
    ],
)
def test_failures_are_status_and_reason_only(argv, code, piped_stdin, capsys):
    piped_stdin("")
    assert _run(argv) == code
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}
