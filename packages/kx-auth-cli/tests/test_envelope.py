"""`kx_auth_cli.envelope` — the one output boundary, pinned on its own.

Every command's tests exercise the envelope through that command. These pin the module directly: the
exception-to-status/exit mapping, each envelope form `guarded` can produce, the human-mode conventions,
the single `--json` declaration reaching every leaf parser, and the fastmcp-free import graph.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

import pytest

from kx_auth_cli import cli, envelope
from kx_auth_cli.envelope import AuthRequired, CliError, Denied, UsageError, guarded


def _args(json_mode: bool) -> argparse.Namespace:
    return argparse.Namespace(json=json_mode)


def test_exit_constants_are_the_documented_five():
    assert (envelope.EXIT_OK, envelope.EXIT_ERROR, envelope.EXIT_USAGE,
            envelope.EXIT_AUTH_REQUIRED, envelope.EXIT_DENIED) == (0, 1, 2, 3, 4)


@pytest.mark.parametrize(
    "cls,status,code",
    [
        (CliError, "error", 1),
        (UsageError, "error", 2),
        (AuthRequired, "auth_required", 3),
        (Denied, "denied", 4),
    ],
)
def test_each_error_carries_its_status_and_exit_code(cls, status, code, capsys):
    assert (cls.status, cls.exit_code) == (status, code)

    def fn():
        raise cls("because")

    assert guarded(_args(True), fn) == code
    out = json.loads(capsys.readouterr().out)
    assert out == {"status": status, "reason": "because"}


def test_usage_error_is_not_a_value_error():
    """A dependency's bare ValueError must land as an operational error, never as "usage"."""
    assert not issubclass(UsageError, ValueError)


def test_success_nests_the_result(capsys):
    assert guarded(_args(True), lambda: {"a": 1}) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "ok", "result": {"a": 1}}


def test_bare_success_has_no_result_key(capsys):
    assert guarded(_args(True), lambda: None) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "ok"}


def test_a_refusal_may_carry_the_decision_it_made(capsys):
    def fn():
        raise Denied(result={"allowed": False})

    assert guarded(_args(True), fn) == 4
    assert json.loads(capsys.readouterr().out) == {"status": "denied", "result": {"allowed": False}}


def test_an_error_may_carry_both_result_and_reason(capsys):
    def fn():
        raise CliError("lint tripped", result={"failed": True})

    assert guarded(_args(True), fn) == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "error", "result": {"failed": True}, "reason": "lint tripped",
    }


def test_an_unclassified_exception_is_an_operational_error_not_a_traceback(capsys):
    def fn():
        raise RuntimeError("boom")

    assert guarded(_args(True), fn) == 1
    assert json.loads(capsys.readouterr().out) == {"status": "error", "reason": "RuntimeError: boom"}


def test_human_mode_success_uses_the_renderer_or_json(capsys):
    assert guarded(_args(False), lambda: {"a": 1}, human=lambda r: f"got {r['a']}") == 0
    assert capsys.readouterr().out == "got 1\n"
    assert guarded(_args(False), lambda: {"a": 1}) == 0
    assert json.loads(capsys.readouterr().out) == {"a": 1}
    assert guarded(_args(False), lambda: None) == 0
    assert capsys.readouterr().out == "ok\n"


def test_human_mode_failure_keeps_stdout_clean(capsys):
    def fn():
        raise UsageError("no token provided")

    assert guarded(_args(False), fn) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "error: no token provided\n"


def test_human_mode_reasonless_refusal_prints_the_status_alone(capsys):
    def fn():
        raise Denied(result={"allowed": False})

    assert guarded(_args(False), fn) == 4
    out, err = capsys.readouterr()
    assert out == "" and err == "denied\n"


def test_note_goes_to_stderr(capsys):
    envelope.note("note: something")
    out, err = capsys.readouterr()
    assert out == "" and err == "note: something\n"


def _leaves(parser: argparse.ArgumentParser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                if "func" in sub._defaults:
                    yield sub
                yield from _leaves(sub)


def test_every_leaf_parser_accepts_json():
    leaves = list(_leaves(cli.build_parser()))
    assert len(leaves) == 14, [leaf.prog for leaf in leaves]  # 4 auth + 10 rbac
    for leaf in leaves:
        assert any(a.dest == "json" for a in leaf._actions), f"{leaf.prog} has no --json"


def test_envelope_import_is_fastmcp_free():
    # In a fresh interpreter, not via importlib.reload: reloading this module would re-create the
    # exception classes and break `except CliError` identity for every command already imported.
    probe = "import sys, kx_auth_cli.envelope; sys.exit(1 if 'fastmcp' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-c", probe], check=False).returncode == 0
