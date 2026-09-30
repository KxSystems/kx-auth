"""`kx auth assert` end to end through the argparse entry point.

Covers the project-only path (no kdb+, no PyKX), the claims-source matrix, the usage/error/denied
exit codes, and the --connect handshake with PyKX stubbed via sys.modules. Also asserts the base CLI
import graph stays fastmcp-free (the kx-auth-cli charter).
"""

from __future__ import annotations

import io
import json
import stat
import sys
import types

import jwt
import pytest

from kx_auth_cli import cli

_HS256_KEY = "test-secret-key-at-least-32-bytes-long!"


def _jwt(**claims) -> str:
    return jwt.encode(claims, _HS256_KEY, algorithm="HS256")


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    return code if isinstance(code, int) else 1


@pytest.fixture(autouse=True)
def _no_ambient_token(monkeypatch):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("KX_AUTH_KDB_PASSWORD", raising=False)


# --- project-only (no --connect): the shared projection, no PyKX --------------------------------


def test_project_only_emits_wire_dict(capsys):
    code = _run([
        "auth", "assert",
        "--principal", json.dumps({"sub": "alice", "scope": "kdbx.read", "aud": "kx-mcp"}),
        "--json",
    ])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert env["status"] == "ok"
    assert env["result"]["principal"]["sub"] == "alice"
    assert env["result"]["principal"]["scopes"] == ["kdbx.read"]
    assert env["result"]["principal"]["aud"] == "kx-mcp"


def test_claims_from_token_decoded_unverified(capsys):
    token = _jwt(sub="bob", scope="kdbx.read", aud="kx-mcp")
    code = _run(["auth", "assert", "--token", token, "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["result"]["principal"]["sub"] == "bob"


def test_no_principal_is_usage_error():
    assert _run(["auth", "assert", "--json"]) == 2


def test_bad_json_is_error(capsys):
    code = _run(["auth", "assert", "--principal", "{not json", "--json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"


# --- --principal input forms: stdin ('-') and @file --------------------------------------------


def test_principal_dash_reads_piped_json(piped_stdin, capsys):
    piped_stdin(json.dumps({"sub": "alice", "scope": "kdbx.read"}))
    code = _run(["auth", "assert", "--principal", "-", "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["result"]["principal"]["sub"] == "alice"


@pytest.mark.parametrize("missing", [False, True])
def test_principal_at_file(tmp_path, capsys, missing):
    path = tmp_path / "principal.json"
    if missing:
        code = _run(["auth", "assert", "--principal", f"@{path}", "--json"])
        assert code == 1  # error, not usage 2 — the point of this case
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["status"] == "error"
        assert "cannot read principal file" in envelope["reason"]
    else:
        path.write_text(json.dumps({"sub": "alice", "scope": "kdbx.read"}))
        code = _run(["auth", "assert", "--principal", f"@{path}", "--json"])
        assert code == 0
        assert json.loads(capsys.readouterr().out)["result"]["principal"]["sub"] == "alice"


# --- --connect handshake with a stubbed PyKX ----------------------------------------------------


class _FakeConn:
    """Records q calls; .kx.auth.valid[] -> True; an optional probe denial is configurable."""

    def __init__(self, *, probe_denied=False, current=None, current_raises=False):
        self.calls = []
        self._probe_denied = probe_denied
        self._current = current
        self._current_raises = current_raises

    def __call__(self, expr, *args):
        self.calls.append((expr, args))
        if expr == ".kx.auth.valid[]":
            return types.SimpleNamespace(py=lambda: True)
        if expr == ".kx.auth.current[]":
            if self._current_raises:
                raise RuntimeError("nyi")
            return types.SimpleNamespace(py=lambda: self._current)
        if self._probe_denied and expr.startswith("select"):
            raise RuntimeError("denied: principal lacks kdbx.read scope")
        return types.SimpleNamespace(py=lambda: None)


class _FakeCharVector:
    """Stands in for kx.CharVector so the wrapping is observable without PyKX installed."""

    def __init__(self, s):
        self.s = s

    def __eq__(self, other):
        return isinstance(other, _FakeCharVector) and other.s == self.s


def _install_fake_pykx(monkeypatch, conn):
    fake = types.ModuleType("pykx")
    fake.SyncQConnection = lambda **kwargs: conn
    fake.CharVector = _FakeCharVector
    monkeypatch.setitem(sys.modules, "pykx", fake)


def test_connect_binds_and_confirms(monkeypatch, capsys):
    conn = _FakeConn()
    _install_fake_pykx(monkeypatch, conn)
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice", "scope": "kdbx.read"}),
        "--connect", "localhost:5010", "--user", "kxmcp", "--password", "pw", "--json",
    ])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert env["status"] == "ok" and env["result"]["bound"] is True and env["result"]["valid"] is True
    bind_calls = [c for c in conn.calls if c[0] == ".kx.auth.bind"]
    assert len(bind_calls) == 1 and bind_calls[0][1][0]["sub"] == "alice"


def test_ferried_claim_strings_are_char_vectors(monkeypatch, capsys):
    """Claim strings must not arrive as q symbols — they never get collected, and `jti` is unique.

    The promoted top-level fields are exempt: q's promote expects symbols there, and they are
    low-cardinality by construction. So the assertion is specifically that `claims` is wrapped and
    `sub` is not.
    """
    conn = _FakeConn()
    _install_fake_pykx(monkeypatch, conn)
    code = _run([
        "auth", "assert",
        "--principal", json.dumps({"sub": "alice", "jti": "unique-per-token", "scope": "kdbx.read"}),
        "--connect", "localhost:5010", "--json",
    ])
    assert code == 0
    ferried = [c for c in conn.calls if c[0] == ".kx.auth.bind"][0][1][0]
    assert ferried["claims"]["jti"] == _FakeCharVector("unique-per-token")
    assert ferried["claims"]["sub"] == _FakeCharVector("alice")
    assert ferried["sub"] == "alice"  # promoted field, left as a symbol
    # The displayed principal stays JSON-serialisable — the wrapping is a wire concern only.
    assert json.loads(capsys.readouterr().out)["result"]["principal"]["claims"]["jti"] == "unique-per-token"


def test_readback_reports_the_promoted_principal(monkeypatch, capsys):
    """The `current[]` readback is what a handshake buys over a projection: q's promoted answer.

    `groups` here is resolved q-side from the host's claim paths, so it appears in `promoted` but not
    in the projected `principal` — which is exactly the distinction the readback exists to show.
    Char vectors arrive as bytes from `.py()` and must be decoded, not printed as a Python repr.
    """
    conn = _FakeConn(current={"sub": "alice", "groups": ["trader"], "iss": b"https://idp"})
    _install_fake_pykx(monkeypatch, conn)
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--json",
    ])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert env["result"]["promoted"] == {"sub": "alice", "groups": ["trader"], "iss": "https://idp"}
    assert "groups" not in env["result"]["principal"]
    assert any(c[0] == ".kx.auth.current[]" for c in conn.calls)


def test_unreadable_readback_still_succeeds(monkeypatch, capsys):
    """Best-effort: a target that binds and validates is working, so a failed readback is not an error."""
    conn = _FakeConn(current_raises=True)
    _install_fake_pykx(monkeypatch, conn)
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--json",
    ])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert env["status"] == "ok" and env["result"]["valid"] is True and "promoted" not in env["result"]


def test_promoted_out_writes_q_principal_atomically(monkeypatch, tmp_path, capsys):
    conn = _FakeConn(current={"sub": "alice", "groups": ["trader"]})
    _install_fake_pykx(monkeypatch, conn)
    target = tmp_path / "principal.json"
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--promoted-out", str(target), "--json",
    ])
    assert code == 0
    assert json.loads(target.read_text()) == {"sub": "alice", "groups": ["trader"]}
    assert not target.with_suffix(".json.tmp").exists()
    # Owner-only, like the login cache: not a credential, but an identity's claims all the same.
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    capsys.readouterr()


def test_promoted_out_requires_connect():
    assert _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--promoted-out", "principal.json",
    ]) == 2


def test_probe_denial_maps_to_exit_4(monkeypatch, capsys):
    conn = _FakeConn(probe_denied=True)
    _install_fake_pykx(monkeypatch, conn)
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "bob"}),
        "--connect", "localhost:5010", "--probe", "select from trades", "--json",
    ])
    assert code == 4
    assert json.loads(capsys.readouterr().out)["status"] == "denied"


def test_connect_without_pykx_is_error(monkeypatch, capsys):
    # Simulate PyKX not installed: importing pykx raises.
    monkeypatch.setitem(sys.modules, "pykx", None)
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--json",
    ])
    assert code == 1
    assert "PyKX" in json.loads(capsys.readouterr().out)["reason"]


# --- charter: the base CLI import graph stays fastmcp-free --------------------------------------


def test_assert_cmd_import_is_fastmcp_free():
    """Importing the command must not pull fastmcp into the process (the CLI ships light)."""
    sys.modules.pop("fastmcp", None)
    import importlib

    import kx_auth_cli.assert_cmd  # noqa: F401

    importlib.reload(kx_auth_cli.assert_cmd)
    assert "fastmcp" not in sys.modules


# Regression for finding kx-auth-cli #5 — usage refusals print bare text and emit no JSON envelope.
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(
            ["auth", "assert", "--principal", '{"sub":"a"}', "--promoted-out", "PROMOTED", "--json"],
            id="promoted-out-without-connect",
        ),
        pytest.param(["auth", "assert", "--json"], id="no-principal"),
    ],
)
def test_an_assert_usage_refusal_still_emits_an_envelope_under_json(
    argv, tmp_path, piped_stdin, json_envelope
):
    piped_stdin("")
    argv = [str(tmp_path / "promoted.json") if arg == "PROMOTED" else arg for arg in argv]
    code, envelope = json_envelope(argv)
    assert code == 2, f"an assert usage refusal must stay exit 2, got {code}"
    assert envelope["status"] == "error", envelope


# Regression for finding kx-auth-cli #13 — assert --principal - reads stdin with no isatty check and
# no OSError guard.
@pytest.mark.parametrize("hostile", ["unreadable", "tty"])
def test_assert_principal_dash_refuses_a_stdin_it_cannot_read(
    hostile, monkeypatch, json_envelope
):
    stream = io.StringIO("")
    if hostile == "unreadable":
        stream.isatty = lambda: False  # type: ignore[method-assign]
        stream.read = lambda *_a: (_ for _ in ()).throw(  # type: ignore[method-assign]
            OSError(5, "Input/output error")
        )
    else:
        stream.isatty = lambda: True  # type: ignore[method-assign]
    monkeypatch.setattr("sys.stdin", stream)
    code, envelope = json_envelope(["auth", "assert", "--principal", "-", "--json"])
    assert code == 2, f"an unusable stdin is a usage error, expected exit 2, got {code}: {envelope!r}"
    assert "stdin" in json.dumps(envelope), (
        f"the refusal did not mention stdin, so it is not actionable: {envelope!r}"
    )


# --- the envelope shape: {status, result} on success, {status, reason} on failure ------------------


def test_project_only_result_carries_only_the_principal(capsys):
    _run(["auth", "assert", "--principal", json.dumps({"sub": "alice"}), "--json"])
    env = json.loads(capsys.readouterr().out)
    assert set(env) == {"status", "result"} and set(env["result"]) == {"principal"}


def test_handshake_result_names_its_fields(monkeypatch, capsys):
    _install_fake_pykx(monkeypatch, _FakeConn(current={"sub": "alice"}))
    _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--json",
    ])
    env = json.loads(capsys.readouterr().out)
    assert set(env) == {"status", "result"}
    assert set(env["result"]) == {"principal", "bound", "valid", "probed", "promoted"}


def test_failures_are_status_and_reason_only(capsys):
    _run(["auth", "assert", "--principal", "{not json", "--json"])
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}
    _run(["auth", "assert", "--json"])
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}


def test_probe_denial_keeps_the_handshake_result_beside_its_reason(monkeypatch, capsys):
    """The bind succeeded; only the probe was refused. Throwing the handshake away would hide that."""
    _install_fake_pykx(monkeypatch, _FakeConn(probe_denied=True))
    code = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "bob"}),
        "--connect", "localhost:5010", "--probe", "select from trades", "--json",
    ])
    env = json.loads(capsys.readouterr().out)
    assert code == 4 and env["status"] == "denied"
    assert env["result"]["bound"] is True and "reason" in env


# --- bind triage: q names two refusals of the caller's input; only an unnamed failure gets the hint --


class _BindRefusingConn(_FakeConn):
    def __init__(self, message):
        super().__init__()
        self._message = message

    def __call__(self, expr, *args):
        if expr == ".kx.auth.bind":
            raise RuntimeError(self._message)
        return super().__call__(expr, *args)


@pytest.mark.parametrize(
    "message,code,status,hint",
    [
        ("denied: caller svc not permitted to assert identity (grant `assert on `kx.identity)", 4, "denied", False),
        ("kx.auth: malformed principal: sub must be a non-null symbol atom, got 11h", 1, "error", False),
        ("nyi", 1, "error", True),
    ],
    ids=["assert-gate-refusal", "malformed-principal", "module-missing"],
)
def test_bind_failures_are_classified_by_qs_message(message, code, status, hint, monkeypatch, capsys):
    _install_fake_pykx(monkeypatch, _BindRefusingConn(message))
    got = _run([
        "auth", "assert", "--principal", json.dumps({"sub": "alice"}),
        "--connect", "localhost:5010", "--json",
    ])
    env = json.loads(capsys.readouterr().out)
    assert (got, env["status"]) == (code, status)
    assert ("target missing the kx.auth module?" in env["reason"]) is hint
    if not hint:
        assert env["reason"] == message  # q's own words, verbatim — they are already actionable
