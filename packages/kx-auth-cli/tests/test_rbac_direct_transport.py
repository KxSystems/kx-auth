"""`rbac.DirectTransport` — the real qIPC dispatch — with a recording fake connection.

Every `rbac` CLI-level test in `test_rbac_cli.py` fakes the whole transport via `_transport`, so
`DirectTransport.call`'s own q-expression construction (which lambda, which arguments, in what
order) has no coverage there at all. Here the fake stands in only for the qIPC connection, so the
actual expression strings and argument tuples `rbac.py` sends are what gets asserted — the only
thing in this suite that would catch a broken q expression before the live-kdb+ demo does.
"""

from __future__ import annotations

import argparse
import json
import sys
import types

import pytest

from kx_auth_cli import envelope, rbac


class _RecordingConn:
    """Records every (expr, args) call; returns a canned value for the first response whose
    keyword substring appears in the expression, or raises a configured exception."""

    def __init__(self, responses=None, raises=None):
        self.calls: list[tuple[str, tuple]] = []
        self._responses = responses or {}
        self._raises = raises

    def __call__(self, expr, *args):
        self.calls.append((expr, args))
        if self._raises is not None:
            raise self._raises
        for keyword, value in self._responses.items():
            if keyword in expr:
                return value
        return None


def _fake_pykx(monkeypatch, *, conn=None, connect_exc=None, connect_kwargs=None):
    """Install a stand-in `pykx` module (qbridge.import_pykx() does a plain `import pykx`, so
    sys.modules injection works unchanged here, same as the assert --connect tests)."""
    fake = types.ModuleType("pykx")

    def _sync_q_connection(**kwargs):
        if connect_kwargs is not None:
            connect_kwargs.update(kwargs)
        if connect_exc is not None:
            raise connect_exc
        return conn

    fake.SyncQConnection = _sync_q_connection
    monkeypatch.setitem(sys.modules, "pykx", fake)


def _args(connect="q:5010", user="svc", password="pw", timeout=5.0, tls=False):
    return argparse.Namespace(connect=connect, user=user, password=password, timeout=timeout, tls=tls)


# --- DirectTransport.open() --------------------------------------------------------------------


def test_open_requires_pykx(monkeypatch):
    monkeypatch.setitem(sys.modules, "pykx", None)
    with pytest.raises(envelope.CliError, match="PyKX is required"):
        rbac.DirectTransport.open(_args())


def test_open_rejects_a_connect_with_no_colon(monkeypatch):
    _fake_pykx(monkeypatch, conn=object())
    with pytest.raises(envelope.UsageError, match="HOST:PORT"):
        rbac.DirectTransport.open(_args(connect="q"))


def test_open_rejects_a_non_numeric_port(monkeypatch):
    _fake_pykx(monkeypatch, conn=object())
    with pytest.raises(envelope.UsageError, match="HOST:PORT"):
        rbac.DirectTransport.open(_args(connect="q:abc"))


def test_open_keeps_a_bracketed_ipv6_host(monkeypatch):
    captured: dict = {}
    _fake_pykx(monkeypatch, conn=object(), connect_kwargs=captured)
    rbac.DirectTransport.open(_args(connect="[::1]:5010"))
    assert captured["host"] == "[::1]"
    assert captured["port"] == 5010


def test_open_defaults_an_empty_host_to_localhost(monkeypatch):
    captured: dict = {}
    _fake_pykx(monkeypatch, conn=object(), connect_kwargs=captured)
    rbac.DirectTransport.open(_args(connect=":5010"))
    assert captured["host"] == "localhost"


def test_open_forwards_credentials_and_timeout(monkeypatch):
    captured: dict = {}
    _fake_pykx(monkeypatch, conn=object(), connect_kwargs=captured)
    rbac.DirectTransport.open(_args(
        connect="q:5010", user="svc", password="pw", timeout=9.0, tls=True,
    ))
    assert captured == {
        "host": "q", "port": 5010, "username": "svc",
        "password": "pw", "timeout": 9.0, "tls": True,
    }


def test_open_wraps_a_connect_failure(monkeypatch):
    _fake_pykx(monkeypatch, connect_exc=RuntimeError("refused"))
    with pytest.raises(envelope.CliError, match="connect failed"):
        rbac.DirectTransport.open(_args())


# --- call(): expression construction -----------------------------------------------------------


def test_grants_expression():
    conn = _RecordingConn(responses={".kx.rbac.grants[]": {"grp": [], "act": [], "res": []}})
    rbac.DirectTransport(conn).call("grants")
    assert conn.calls[0][0] == ".kx.rbac.grants[]"


def test_current_expression_and_json_roundtrip():
    conn = _RecordingConn(responses={".kx.auth.current[]": json.dumps({"sub": "alice"})})
    result = rbac.DirectTransport(conn).call("current")
    assert conn.calls[0][0] == ".j.j .kx.auth.current[]"
    assert result == {"sub": "alice"}


def test_check_uses_the_plain_lambda_and_is_not_json_decoded():
    conn = _RecordingConn(responses={"kx.rbac.check": True})
    result = rbac.DirectTransport(conn).call("check", {
        "principal": {"sub": "alice"}, "action": "read", "resource": "data.trades",
    })
    expr, args = conn.calls[0]
    assert expr == "{[p;a;r] .kx.rbac.check[p;`$string a;`$string r]}"
    assert args == ({"sub": "alice"}, "read", "data.trades")
    assert result is True


def test_explain_uses_the_jj_wrapped_lambda_and_is_json_decoded():
    conn = _RecordingConn(responses={"kx.rbac.explain": json.dumps({"allowed": False})})
    result = rbac.DirectTransport(conn).call("explain", {
        "principal": {"sub": "alice"}, "action": "read", "resource": "data.trades",
    })
    expr, _ = conn.calls[0]
    assert expr == "{[p;a;r] .j.j .kx.rbac.explain[p;`$string a;`$string r]}"
    assert result == {"allowed": False}


def test_check_with_no_principal_defaults_via_current():
    conn = _RecordingConn(responses={
        ".kx.auth.current[]": json.dumps({"sub": "alice"}),
        "kx.rbac.check": True,
    })
    rbac.DirectTransport(conn).call("check", {
        "principal": None, "action": "read", "resource": "data.trades",
    })
    assert conn.calls[0][0] == ".j.j .kx.auth.current[]"  # current[] fetched first
    assert conn.calls[1][1][0] == {"sub": "alice"}  # then used as the principal


def test_none_action_and_resource_are_ferried_as_empty_strings():
    conn = _RecordingConn(responses={"kx.rbac.check": True})
    rbac.DirectTransport(conn).call("check", {
        "principal": {"sub": "a"}, "action": None, "resource": None,
    })
    _, args = conn.calls[0]
    assert args[1:] == ("", "")


def test_scope_with_empty_context_sends_empty_parallel_lists(monkeypatch):
    monkeypatch.setitem(sys.modules, "pykx", types.ModuleType("pykx"))
    conn = _RecordingConn(responses={"kx.auth.explain": json.dumps({"allowed": True, "obligations": {}})})
    rbac.DirectTransport(conn).call("scope", {
        "principal": {"sub": "alice"}, "action": "read",
        "resources": ["data.trades"], "context": {},
    })
    expr, args = conn.calls[0]
    assert expr == (
        "{[p;a;rs;k;v] .j.j .kx.auth.explain["
        "p; `$string a; `$string rs; $[count k; (`$string k)!v; (::)]]}"
    )
    assert args == ({"sub": "alice"}, "read", ["data.trades"], [], [])


def test_scope_maps_context_values_onto_q_types_in_key_order(monkeypatch):
    fake_kx = types.ModuleType("pykx")
    fake_kx.SymbolAtom = lambda v: ("sym", v)
    fake_kx.LongAtom = lambda v: ("long", v)
    fake_kx.FloatAtom = lambda v: ("float", v)
    fake_kx.BooleanAtom = lambda v: ("bool", v)
    fake_kx.TimestampAtom = lambda v: ("ts", v)
    monkeypatch.setitem(sys.modules, "pykx", fake_kx)

    conn = _RecordingConn(responses={"kx.auth.explain": json.dumps({"allowed": True, "obligations": {}})})
    rbac.DirectTransport(conn).call("scope", {
        "principal": {"sub": "alice"}, "action": "read",
        "resources": ["data.trades"], "context": {"sym": "AAPL", "limit": 3},
    })
    _, args = conn.calls[0]
    keys, values = args[3], args[4]
    assert keys == ["sym", "limit"]
    assert values == [("sym", "AAPL"), ("long", 3)]  # order matches the declared context keys


def test_apply_builds_the_inline_table_from_column_wise_lists():
    conn = _RecordingConn(responses={"kx.rbac.apply": json.dumps({"changed": True})})
    ops = [
        {"op": "grant", "group": "trader", "action": "read", "resource": "data.trades"},
        {"op": "revoke", "group": "viewer", "action": None, "resource": "data.accounts"},
    ]
    rbac.DirectTransport(conn).call("apply", {"operations": ops, "dry_run": True})
    expr, args = conn.calls[0]
    assert expr == (
        "{[op;g;a;r;d] .j.j .kx.rbac.apply["
        "([] op:`$string op;grp:`$string g;act:`$string a;res:`$string r);d]}"
    )
    assert args == (
        ["grant", "revoke"], ["trader", "viewer"], ["read", ""], ["data.trades", "data.accounts"], True,
    )


def test_replace_builds_the_inline_table_without_an_op_column():
    conn = _RecordingConn(responses={"kx.rbac.replace": json.dumps({"changed": True})})
    grants = [{"group": "trader", "action": "read", "resource": None}]
    rbac.DirectTransport(conn).call("replace", {"grants": grants, "dry_run": False})
    expr, args = conn.calls[0]
    assert expr == (
        "{[g;a;r;d] .j.j .kx.rbac.replace["
        "([] grp:`$string g;act:`$string a;res:`$string r);d]}"
    )
    assert args == (["trader"], ["read"], [""], False)


def test_effective_defaults_principal_via_current():
    conn = _RecordingConn(responses={
        ".kx.auth.current[]": json.dumps({"sub": "alice"}),
        "kx.rbac.effective": {"grp": ["trader"], "act": ["read"], "res": ["data.trades"]},
    })
    rbac.DirectTransport(conn).call("effective", {"principal": None})
    assert conn.calls[0][0] == ".j.j .kx.auth.current[]"
    expr, args = conn.calls[1]
    assert expr == "{[p] .kx.rbac.effective[p]}"
    assert args == ({"sub": "alice"},)


def test_verify_expression_and_json_decode():
    conn = _RecordingConn(responses={".kx.rbac.verify[]": json.dumps({"findings": []})})
    result = rbac.DirectTransport(conn).call("verify")
    assert conn.calls[0][0] == ".j.j .kx.rbac.verify[]"
    assert result == {"findings": []}


@pytest.mark.parametrize("verb", ["save", "load"])
def test_save_and_load_expressions(verb):
    conn = _RecordingConn(responses={f".kx.rbac.{verb}[]": "ok"})
    rbac.DirectTransport(conn).call(verb)
    assert conn.calls[0][0] == f".kx.rbac.{verb}[]"


# --- error triage --------------------------------------------------------------------------------


@pytest.mark.parametrize("message", ["denied: nope", "DENIED: no", "Denied by policy"])
def test_a_denied_prefixed_exception_becomes_denied(message):
    conn = _RecordingConn(raises=RuntimeError(message))
    with pytest.raises(envelope.Denied):
        rbac.DirectTransport(conn).call("grants")


def test_any_other_exception_becomes_rbac_error():
    conn = _RecordingConn(raises=RuntimeError("boom"))
    with pytest.raises(envelope.CliError):
        rbac.DirectTransport(conn).call("grants")


def test_unsupported_operation_name_is_an_rbac_error():
    """Unreachable through the CLI (every real verb funnels through one of the named branches
    above) — worth a test precisely because nothing else exercises the fall-through raise."""
    conn = _RecordingConn()
    with pytest.raises(envelope.CliError, match="unsupported direct operation: bogus"):
        rbac.DirectTransport(conn).call("bogus")
