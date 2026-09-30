"""The kx rbac command contract, with transport calls kept hermetic."""

from __future__ import annotations

import json
import sys
import time
import types

import httpx
import pytest

from kx_auth_cli import cli, envelope, rbac


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    return int(exc.value.code)


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.grants = {
            "grp": ["trader", "viewer"],
            "act": ["read", "query"],
            "res": ["data.trades", "kdbx.sql"],
        }
        self.findings = {
            "severity": ["error", "note"],
            "issue": ["no group can assert an identity", "a total wildcard grant exists"],
            "detail": ["grant assert on kx.identity", "grp=root"],
        }

    def call(self, name, payload=None):
        self.calls.append((name, payload))
        if name == "grants":
            return self.grants
        if name == "check":
            return payload["resource"] == "data.trades"
        if name == "explain":
            return {"allowed": False, "reason": "no grant covers read:data.accounts"}
        if name == "effective":
            return {"grp": ["trader"], "act": ["read"], "res": ["data.trades"]}
        if name == "verify":
            return self.findings
        if name == "save":
            # q hands back a filehandle symbol, colon and all.
            return ":/etc/kx/grants"
        if name == "load":
            return 12
        if name == "scope":
            allowed = any(r == "data.trades" for r in payload["resources"])
            obligations = {}
            if len(payload["resources"]) > 1:
                obligations["resources"] = ["data.trades"]
            if "from" in payload["context"]:
                obligations["from"] = "2026-05-01T00:00:00.000000000"
            return {
                "allowed": allowed, "obligations": obligations,
                "reason": "entitled window starts 2026.05.01",
                "denial": "" if allowed else "denied: nobody not permitted read on data.secret",
            }
        if name in ("apply", "replace"):
            return {
                "dryRun": payload["dry_run"], "changed": True,
                "added": {"grp": ["trader"], "act": ["read"], "res": ["data.trades"]},
                "removed": {"grp": [], "act": [], "res": []}, "findings": [],
                "persisted": not payload["dry_run"],
            }
        return "ok"


@pytest.fixture
def transport(monkeypatch):
    fake = FakeTransport()
    monkeypatch.setattr(rbac, "_transport", lambda _args: fake)
    return fake


def test_show_is_public_and_filterable(transport, capsys):
    code = _run(["rbac", "show", "--connect", "q:5010", "--group", "trader", "--json"])
    assert code == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result == {
        "grants": [{"group": "trader", "action": "read", "resource": "data.trades"}],
    }


def test_human_mode_success_is_bare_json_with_no_envelope(transport, capsys):
    # rbac's one deliberate departure from the other four commands: human-mode success is
    # pretty-printed JSON with no {"status": ...} wrapper, not a one-line summary.
    code = _run(["rbac", "show", "--connect", "q:5010", "--group", "trader"])
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert "status" not in result
    assert result == {"grants": [{"group": "trader", "action": "read", "resource": "data.trades"}]}


def test_human_mode_failure_keeps_stdout_clean(transport, capsys):
    code = _run(["rbac", "check", "read", "--connect", "q:5010"])  # no resource, no colon
    assert code == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.strip() == "error: supply ACTION RESOURCE or ACTION:RESOURCE"


def test_check_pair_denial_is_exit_4(transport, capsys):
    code = _run(["rbac", "check", "read:data.accounts", "--connect", "q:5010", "--json"])
    assert code == 4
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "denied"
    assert transport.calls[-1][1]["principal"] is None


def test_check_explicit_principal_is_decision_input(transport, capsys):
    principal = json.dumps({"sub": "alice", "groups": ["trader"]})
    code = _run([
        "rbac", "check", "read", "data.trades", "--principal", principal,
        "--connect", "q:5010", "--json",
    ])
    assert code == 0
    assert transport.calls[-1][1]["principal"]["sub"] == "alice"
    assert json.loads(capsys.readouterr().out)["result"]["allowed"] is True


@pytest.mark.parametrize(
    "args",
    [
        ["read"],  # no resource, no colon
        ["read:data.trades", "data.accounts"],  # ACTION:RESOURCE plus a separate RESOURCE
        ["", ""],  # empty action and resource
    ],
)
def test_parse_pair_value_errors_are_usage_2(transport, capsys, args):
    code = _run(["rbac", "check", *args, "--connect", "q:5010", "--json"])
    assert code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_run_explain_plain_path_is_near_raw_unlike_check(transport, capsys):
    # No --resource/--ctx: the non-seam branch, answered directly by the engine's own `explain`
    # rather than the seam's `scope`. Assert the transport call name AND that the result is
    # near-raw (carries `reason`, no synthesized action/resource keys) — the contrast with
    # `check`'s reshaped {"allowed", "action", "resource"} the existing tests already cover.
    code = _run(["rbac", "explain", "read:data.accounts", "--connect", "q:5010", "--json"])
    assert code == 4
    assert transport.calls[-1][0] == "explain"
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["reason"] == "no grant covers read:data.accounts"
    assert "action" not in result and "resource" not in result


def test_replace_on_an_operations_file_is_rejected(transport, tmp_path, capsys):
    # The reverse of test_snapshot_requires_replace below: an operations-shaped file with
    # --replace, which the forward case's XOR rejects from the other direction.
    source = tmp_path / "ops.json"
    source.write_text(json.dumps({
        "operations": [{"op": "grant", "group": "trader", "action": "read", "resource": "data.trades"}],
    }))
    code = _run(["rbac", "import", str(source), "--replace", "--connect", "q:5010", "--json"])
    assert code == 2
    assert "not operations" in json.loads(capsys.readouterr().out)["reason"]


def test_grant_is_one_atomic_persisted_operation(transport, capsys):
    code = _run([
        "rbac", "grant", "trader", "read:data.trades", "--connect", "q:5010", "--json",
    ])
    assert code == 0
    name, payload = transport.calls[-1]
    assert name == "apply"
    assert payload == {
        "operations": [{"op": "grant", "group": "trader", "action": "read", "resource": "data.trades"}],
        "dry_run": False,
    }
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["persisted"] is True
    assert result["acknowledgement"] == "grant added"


def test_absent_revoke_succeeds_with_explicit_acknowledgement(transport, monkeypatch, capsys):
    original = transport.call

    def call(name, payload=None):
        result = original(name, payload)
        if name == "apply":
            result["changed"] = False
            result["added"] = {"grp": [], "act": [], "res": []}
        return result

    monkeypatch.setattr(transport, "call", call)
    code = _run(["rbac", "revoke", "viewer", "read:data.missing", "--connect", "q:5010", "--json"])
    assert code == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["changed"] is False
    assert result["acknowledgement"] == "grant did not exist"


def test_operations_import_dry_run_is_an_atomic_preview(transport, tmp_path, capsys):
    source = tmp_path / "ops.json"
    source.write_text(json.dumps({
        "operations": [{"op": "revoke", "group": "viewer", "action": "query", "resource": "kdbx.sql"}],
    }))
    code = _run([
        "rbac", "import", str(source), "--dry-run", "--connect", "q:5010", "--json",
    ])
    assert code == 0
    name, payload = transport.calls[-1]
    assert name == "apply" and payload["dry_run"] is True
    assert json.loads(capsys.readouterr().out)["result"]["changed"] is True


def test_import_rejects_obsolete_concurrency_metadata(transport, tmp_path, capsys):
    source = tmp_path / "ops.json"
    source.write_text(json.dumps({"base_version": 7, "operations": []}))
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 2
    assert "unexpected import field" in json.loads(capsys.readouterr().out)["reason"]


def test_snapshot_requires_replace(transport, tmp_path, capsys):
    source = tmp_path / "snapshot.json"
    source.write_text(json.dumps({"grants": []}))
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 2
    assert "requires --replace" in json.loads(capsys.readouterr().out)["reason"]


def test_snapshot_replace_preserves_json_null_wildcard(transport, tmp_path, capsys):
    source = tmp_path / "snapshot.json"
    source.write_text(json.dumps({
        "grants": [{"group": "admins", "action": None, "resource": None}],
    }))
    code = _run([
        "rbac", "import", str(source), "--replace", "--connect", "q:5010", "--json",
    ])
    assert code == 0
    name, payload = transport.calls[-1]
    assert name == "replace" and payload["grants"][0]["action"] is None
    capsys.readouterr()


def test_import_rejects_a_misspelled_resource_instead_of_creating_a_wildcard(transport, tmp_path, capsys):
    source = tmp_path / "ops.json"
    source.write_text(json.dumps({
        "operations": [{
            "op": "grant", "group": "viewer", "action": "read", "ressource": "data.trades",
        }],
    }))
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 2
    assert "unexpected import field" in json.loads(capsys.readouterr().out)["reason"]


def test_empty_operation_csv_remains_an_operations_import(transport, tmp_path, capsys):
    source = tmp_path / "ops.csv"
    source.write_text("op,group,action,resource\n")
    code = _run(["rbac", "import", str(source), "--dry-run", "--connect", "q:5010", "--json"])
    assert code == 0
    name, payload = transport.calls[-1]
    assert name == "apply" and payload["operations"] == []
    capsys.readouterr()


@pytest.mark.parametrize(
    "content",
    [
        "op,group,action,resource\ngrant,viewer,read\n",
        "group,action,resource\nviewer,read\n",
        "op,group,action,resource\ngrant,viewer,,data.trades\n",
        "group,action,resource\nviewer,read,\n",
    ],
)
def test_csv_requires_explicit_action_and_resource_cells(transport, tmp_path, capsys, content):
    source = tmp_path / "import.csv"
    source.write_text(content)
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 2
    assert "use literal '*'" in json.loads(capsys.readouterr().out)["reason"]


def test_csv_extra_cell_is_a_usage_error_not_a_traceback(transport, tmp_path, capsys):
    source = tmp_path / "ops.csv"
    source.write_text("op,group,action,resource\ngrant,viewer,read,data.trades,unexpected\n")
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "more fields than its header" in envelope["reason"]


def test_csv_literal_star_is_the_only_wildcard_spelling(transport, tmp_path, capsys):
    source = tmp_path / "ops.csv"
    source.write_text("op,group,action,resource\ngrant,admins,*,*\n")
    code = _run(["rbac", "import", str(source), "--connect", "q:5010", "--json"])
    assert code == 0
    assert transport.calls[-1][1]["operations"][0] == {
        "op": "grant", "group": "admins", "action": None, "resource": None,
    }
    capsys.readouterr()


def test_export_writes_portable_json_atomically(transport, tmp_path, capsys):
    target = tmp_path / "grants.json"
    code = _run(["rbac", "export", str(target), "--connect", "q:5010", "--json"])
    assert code == 0
    exported = json.loads(target.read_text())
    assert exported["grants"][0]["resource"] == "data.trades"
    assert not target.with_suffix(".json.tmp").exists()
    capsys.readouterr()


def test_export_write_failure_is_error_1_not_a_traceback(transport, tmp_path, capsys):
    # A regular FILE where the export's parent directory should be: atomic.write_text's own
    # mkdir(parents=True, exist_ok=True) raises FileExistsError, portably (no chmod, no
    # root-sensitivity) — the same failure a typo'd export path would hit in real use.
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    target = blocker / "grants.json"
    code = _run(["rbac", "export", str(target), "--connect", "q:5010", "--json"])
    assert code == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "cannot write export" in envelope["reason"]


def test_import_accepts_the_q_style_grp_act_res_aliases(transport, tmp_path, capsys):
    # Documented alternate input form for a JSON import: grp/act/res instead of group/action/
    # resource. Every other import test in this file uses the public names, so this alias path
    # has otherwise had zero coverage.
    source = tmp_path / "grants.json"
    source.write_text(json.dumps({"grants": [{"grp": "trader", "act": "read", "res": "data.trades"}]}))
    code = _run(["rbac", "import", str(source), "--replace", "--connect", "q:5010", "--json"])
    assert code == 0
    name, payload = transport.calls[-1]
    assert name == "replace"
    assert payload["grants"][0] == {"group": "trader", "action": "read", "resource": "data.trades"}
    capsys.readouterr()


def test_http_transport_uses_cached_login(monkeypatch):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(rbac.cache, "get", lambda server: {"access_token": "cached-token"})
    args = type("Args", (), {"server": "https://gateway", "token": None, "no_verify": False, "timeout": 5.0})()
    transport = rbac.HttpTransport.open(args)
    assert transport.token == "cached-token"
    assert transport.base == "https://gateway/kx/rbac/v1"


def test_http_token_precedence_is_flag_env_cache(monkeypatch):
    monkeypatch.setenv("KX_AUTH_TOKEN", "env-token")
    monkeypatch.setattr(rbac.cache, "get", lambda server: {"access_token": "cached-token"})
    args = type("Args", (), {"server": "https://gateway", "token": "flag-token", "no_verify": False, "timeout": 5.0})()
    assert rbac.HttpTransport.open(args).token == "flag-token"


def test_http_transport_rejects_an_expired_cached_login(monkeypatch):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(rbac.cache, "get", lambda server: {
        "access_token": "expired-token", "expires_at": time.time() - 1,
    })
    args = type("Args", (), {"server": "https://gateway", "token": None, "no_verify": False, "timeout": 5.0})()
    with pytest.raises(envelope.AuthRequired, match="has expired"):
        rbac.HttpTransport.open(args)


@pytest.mark.parametrize(
    ("name", "method", "path"),
    [
        ("grants", "GET", "/grants"),
        ("check", "POST", "/check"),
        ("explain", "POST", "/explain"),
        ("apply", "POST", "/transactions"),
        ("replace", "POST", "/replace"),
        ("save", "POST", "/save"),
        ("load", "POST", "/load"),
    ],
)
def test_http_transport_uses_only_the_fixed_gateway_routes(monkeypatch, name, method, path):
    seen = {}

    def request(actual_method, url, **kwargs):
        seen.update(method=actual_method, url=url, kwargs=kwargs)
        return httpx.Response(
            200,
            json={"result": {"ok": True}},
            request=httpx.Request(actual_method, url),
        )

    monkeypatch.setattr(rbac.httpx, "request", request)
    transport = rbac.HttpTransport("https://gateway/kx/rbac/v1", "bearer", True, 5.0)
    payload = {"some": "input"}
    assert transport.call(name, payload) == {"ok": True}
    assert (seen["method"], seen["url"]) == (method, "https://gateway/kx/rbac/v1" + path)
    assert seen["kwargs"]["headers"] == {"Authorization": "Bearer bearer"}
    assert seen["kwargs"]["json"] == (payload if method == "POST" else None)


@pytest.mark.parametrize(
    ("status", "error"),
    [(401, envelope.AuthRequired), (403, envelope.Denied)],
)
def test_http_transport_maps_authentication_and_policy_refusals(monkeypatch, status, error):
    monkeypatch.setattr(
        rbac.httpx, "request", lambda *args, **kwargs: httpx.Response(status, text="refused"),
    )
    transport = rbac.HttpTransport("https://gateway/kx/rbac/v1", "bearer", True, 5.0)
    with pytest.raises(error, match="refused"):
        transport.call("grants")


def test_show_with_no_bearer_at_all_is_auth_required_3(monkeypatch, capsys):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(rbac.cache, "get", lambda server: {})
    code = _run(["rbac", "show", "--server", "https://gateway", "--json"])
    assert code == 3
    assert json.loads(capsys.readouterr().out)["status"] == "auth_required"


def test_show_with_an_expired_cached_login_is_auth_required_3(monkeypatch, capsys):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(rbac.cache, "get", lambda server: {
        "access_token": "expired", "expires_at": time.time() - 1,
    })
    code = _run(["rbac", "show", "--server", "https://gateway", "--json"])
    assert code == 3
    assert json.loads(capsys.readouterr().out)["status"] == "auth_required"


def test_show_with_a_401_from_the_gateway_is_auth_required_3(monkeypatch, capsys):
    monkeypatch.setattr(rbac.httpx, "request", lambda *a, **k: httpx.Response(401, text="refused"))
    code = _run(["rbac", "show", "--server", "https://gateway", "--token", "t", "--json"])
    assert code == 3
    assert json.loads(capsys.readouterr().out)["status"] == "auth_required"


def test_show_with_an_unsupported_server_scheme_is_error_1(capsys):
    code = _run(["rbac", "show", "--server", "notaurl", "--token", "t", "--json"])
    assert code == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "gateway request failed" in envelope["reason"]


def test_show_with_a_malformed_server_url_exits_cleanly_instead_of_raising(capsys):
    # httpx.InvalidURL does not subclass httpx.HTTPError, so HttpTransport.call used to let it escape
    # as a traceback. Exit 1 (not 2) matches the sibling unsupported-scheme case above: an unusable
    # --server is a transport error here. The envelope assertion is the real contract — an uncaught
    # exception exits 1 too, so the code alone under-specifies this.
    code = _run(["rbac", "show", "--server", "http://[::1", "--token", "t", "--json"])
    assert code == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "gateway request failed" in envelope["reason"]


def test_show_principal_uses_effective_not_grants(transport, capsys):
    principal = json.dumps({"sub": "alice", "groups": ["trader"]})
    code = _run(["rbac", "show", "--principal", principal, "--connect", "q:5010", "--json"])
    assert code == 0
    assert transport.calls[-1][0] == "effective"
    assert transport.calls[-1][1]["principal"]["sub"] == "alice"
    assert json.loads(capsys.readouterr().out)["result"] == {
        "grants": [{"group": "trader", "action": "read", "resource": "data.trades"}],
    }


def test_show_without_principal_still_reads_the_public_table(transport, capsys):
    code = _run(["rbac", "show", "--connect", "q:5010", "--json"])
    assert code == 0
    assert transport.calls[-1][0] == "grants"
    assert len(json.loads(capsys.readouterr().out)["result"]["grants"]) == 2


def test_show_principal_and_group_compose(transport, capsys):
    principal = json.dumps({"sub": "alice", "groups": ["trader"]})
    code = _run([
        "rbac", "show", "--principal", principal, "--group", "viewer",
        "--connect", "q:5010", "--json",
    ])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["result"] == {"grants": []}


def test_verify_reports_findings_and_counts(transport, capsys):
    code = _run(["rbac", "verify", "--connect", "q:5010", "--json"])
    assert code == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["counts"] == {"error": 1, "warning": 0, "note": 1}
    assert result["findings"][0]["severity"] == "error"
    assert "assert an identity" in result["findings"][0]["issue"]
    assert "failed" not in result


def test_verify_without_fail_on_exits_zero_despite_an_error(transport, capsys):
    code = _run(["rbac", "verify", "--connect", "q:5010", "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["result"]["counts"]["error"] == 1


def test_verify_fail_on_error_exits_1_and_keeps_the_findings(transport, capsys):
    code = _run(["rbac", "verify", "--fail-on", "error", "--connect", "q:5010", "--json"])
    assert code == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert envelope["result"]["failed"] is True
    assert envelope["result"]["counts"]["error"] == 1
    assert "1 error" in envelope["reason"]


def test_verify_fail_on_is_not_a_denial(transport, capsys):
    """A tripped lint is exit 1, never exit 4. Nothing was refused."""
    code = _run(["rbac", "verify", "--fail-on", "error", "--connect", "q:5010", "--json"])
    assert code == 1 and code != 4


def test_verify_fail_on_warning_is_not_tripped_by_a_note(transport, capsys):
    transport.findings = {"severity": ["note"], "issue": ["a total wildcard grant exists"], "detail": ["x"]}
    code = _run(["rbac", "verify", "--fail-on", "warning", "--connect", "q:5010", "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["result"]["failed"] is False


def test_verify_on_a_clean_policy_reports_nothing(transport, capsys):
    transport.findings = {"severity": [], "issue": [], "detail": []}
    code = _run(["rbac", "verify", "--fail-on", "error", "--connect", "q:5010", "--json"])
    assert code == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["findings"] == []
    assert result["counts"] == {"error": 0, "warning": 0, "note": 0}
    assert result["failed"] is False


def test_verify_requires_a_transport():
    assert _run(["rbac", "verify", "--json"]) == 2


def test_save_names_the_store_path_it_wrote(transport, capsys):
    """save/load results name their own field rather than nesting a second "result"."""
    code = _run(["rbac", "save", "--connect", "q:5010", "--json"])
    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "ok"
    # The colon is a q filehandle artifact and must not reach the envelope.
    assert envelope["result"] == {"path": "/etc/kx/grants"}
    assert "result" not in envelope["result"]


def test_load_names_the_grant_count_it_installed(transport, capsys):
    code = _run(["rbac", "load", "--connect", "q:5010", "--json"])
    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["result"] == {"grants": 12}
    assert "result" not in envelope["result"]


# ---- the context axis and many-resource forms, both OPTIONAL ------------------------------------
# The point of these four: asking the old question must still take the old route, and asking a question
# only the seam can answer must take the seam's.


def test_single_resource_without_context_still_asks_the_engine(transport, capsys):
    code = _run(["rbac", "check", "read", "data.trades", "--connect", "q:5010", "--json"])
    assert code == 0
    assert [name for name, _ in transport.calls] == ["check"]
    assert json.loads(capsys.readouterr().out)["result"] == {
        "allowed": True, "action": "read", "resource": "data.trades",
    }


def test_many_resources_ask_the_seam_and_return_the_subset(transport, capsys):
    code = _run([
        "rbac", "check", "read", "data.trades",
        "--resource", "data.secret", "--connect", "q:5010", "--json",
    ])
    assert code == 0
    name, payload = transport.calls[0]
    assert name == "scope"
    assert payload["resources"] == ["data.trades", "data.secret"]
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["obligations"] == {"resources": ["data.trades"]}
    assert result["declared"] == []


def test_declared_context_is_reported_alongside_its_narrowing(transport, capsys):
    code = _run([
        "rbac", "explain", "read", "data.trades",
        "--ctx", json.dumps({"from": "2026-01-01T00:00:00", "syms": ["AAPL", "MSFT"]}),
        "--connect", "q:5010", "--json",
    ])
    assert code == 0
    name, payload = transport.calls[0]
    assert name == "scope"
    assert sorted(payload["context"]) == ["from", "syms"]
    result = json.loads(capsys.readouterr().out)["result"]
    # `declared` is what makes the answer auditable: an obligation is only legitimate on a declared axis.
    assert result["declared"] == ["from", "syms"]
    assert result["obligations"]["from"] == "2026-05-01T00:00:00.000000000"
    assert result["reason"].startswith("entitled window")


def test_seam_refusal_is_still_exit_4_and_carries_its_denial(transport, capsys):
    code = _run([
        "rbac", "check", "read", "data.secret",
        "--ctx", "{}", "--connect", "q:5010", "--json",
    ])
    assert code == 4
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "denied"
    assert "not permitted" in envelope["result"]["denial"]


def test_context_must_be_a_json_object(transport, capsys):
    assert _run(["rbac", "check", "read", "data.trades", "--ctx", "[1,2]", "--connect", "q:5010", "--json"]) == 2
    assert _run(["rbac", "check", "read", "data.trades", "--ctx", "{oops", "--connect", "q:5010", "--json"]) == 2


def test_wildcard_resource_cannot_be_combined_with_the_seam_forms(transport):
    # `*` means "no resource named", which has nothing for the seam to narrow.
    assert _run(["rbac", "check", "read", "*", "--ctx", "{}", "--connect", "q:5010", "--json"]) == 2


# ---- the JSON-to-q value mapping is part of the CLI contract ------------------------------------


def test_json_context_values_map_onto_q_types():
    kx = pytest.importorskip("pykx")
    assert rbac._to_q(kx, "syms", ["AAPL", "MSFT"]).t == 11
    assert rbac._to_q(kx, "sym", "AAPL").t == -11
    # An ISO-8601 string becomes a timestamp, because the seam requires an obligation to carry the same q
    # type the caller declared, and JSON has no timestamp of its own.
    assert rbac._to_q(kx, "from", "2026-01-01T00:00:00").t == -12
    assert rbac._to_q(kx, "limit", 100).t == -7
    assert rbac._to_q(kx, "ratio", 0.5).t == -9
    assert rbac._to_q(kx, "live", True).t == -1


def test_a_heterogeneous_or_empty_context_axis_is_refused():
    kx = pytest.importorskip("pykx")
    for bad in ([], ["AAPL", 3], [{"a": 1}]):
        with pytest.raises(envelope.UsageError):
            rbac._to_q(kx, "syms", bad)
    with pytest.raises(envelope.UsageError):
        rbac._to_q(kx, "nested", {"a": 1})


# Regression for finding kx-auth-cli #3 — bool(readable(result)) fails open on a non-boolean check
# result.
@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("false", id="the-string-false"),
        pytest.param("denied", id="a-denial-string"),
        pytest.param({"allowed": False}, id="a-dict-that-says-not-allowed"),
        pytest.param({"result": {"allowed": False}}, id="the-nested-gateway-shape"),
        pytest.param([0], id="a-one-element-q-boolean-vector"),
    ],
)
def test_rbac_check_never_reads_a_non_boolean_as_allowed(bad, monkeypatch, json_envelope):
    class _T:
        def call(self, _name, _payload=None):
            return bad

    monkeypatch.setattr(rbac, "_transport", lambda _a: _T())
    code, envelope = json_envelope(
        ["rbac", "check", "read", "data.x", "--connect", "q:1", "--json"]
    )
    result = envelope.get("result")
    allowed = result.get("allowed") if isinstance(result, dict) else None
    assert not (code == 0 and allowed is True), (
        f"a {type(bad).__name__} q answer was read as ALLOWED: {envelope!r}"
    )


# Regression for finding kx-auth-cli #2 — malformed decisions and ragged tables escape as
# tracebacks.
@pytest.mark.parametrize(
    "argv,result",
    [
        pytest.param(
            ["rbac", "check", "read", "data.x", "--resource", "data.y", "--connect", "q:1", "--json"],
            ["nope"],
            id="scope-returned-a-list",
        ),
        pytest.param(
            ["rbac", "show", "--connect", "q:1", "--json"],
            {"grp": ["a", "b"], "act": ["read"], "res": ["x", "y"]},
            id="a-ragged-grant-table",
        ),
    ],
)
def test_a_malformed_gateway_response_is_refused_not_a_crash(
    argv, result, monkeypatch, json_envelope
):
    class _T:
        def call(self, _name, _payload=None):
            return result

    monkeypatch.setattr(rbac, "_transport", lambda _a: _T())
    code, envelope = json_envelope(argv)
    assert code == 1, f"a malformed server response should be exit 1, got {code}: {envelope!r}"
    assert envelope["status"] == "error", envelope


def _fake_pykx(monkeypatch, response):
    fake = types.ModuleType("pykx")
    fake.SyncQConnection = lambda **_k: (lambda _expr, *_a: response)
    monkeypatch.setitem(sys.modules, "pykx", fake)


# Regression for finding kx-auth-cli #4 — a bad --principal file is exit 2 and a bad --ctx value is
# exit 1; both are the wrong way round.
def test_bad_file_contents_and_bad_flag_values_do_not_share_an_exit_code(
    monkeypatch, tmp_path, json_envelope
):
    bad_json = tmp_path / "principal.json"
    bad_json.write_text("{not json")

    class _T:
        def call(self, _name, _payload=None):
            return False

    monkeypatch.setattr(rbac, "_transport", lambda _a: _T())
    code, envelope = json_envelope(
        ["rbac", "check", "read", "data.x", "--principal", f"@{bad_json}", "--connect", "q:1", "--json"]
    )
    assert code == 1, f"unparseable file contents should be exit 1, got {code}: {envelope!r}"

    monkeypatch.undo()
    _fake_pykx(monkeypatch, '{"allowed":false}')
    code, envelope = json_envelope(
        ["rbac", "check", "read", "data.x", "--ctx", '{"from":[1,"a"]}', "--connect", "q:1", "--json"]
    )
    assert code == 2, f"a malformed --ctx value should be exit 2, got {code}: {envelope!r}"


# Regression for finding kx-auth-cli #7 and #2b — a non-numeric cached expires_at reaches an
# unguarded float() in rbac.
def test_rbac_refuses_a_corrupt_cached_expiry(monkeypatch, tmp_path, json_envelope):
    from kx_auth_cli import cache

    monkeypatch.setenv("KX_AUTH_CACHE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)
    cache.save("https://mcp.test", {"access_token": "at", "expires_at": {"a": 1}})
    code, envelope = json_envelope(
        ["rbac", "show", "--server", "https://mcp.test", "--json"]
    )
    assert code != 0, f"rbac used a credential whose expiry it could not read: {envelope!r}"
