"""Non-JSON (human-readable) output — untested everywhere else in the suite, since every
exit-code/branch test elsewhere passes `--json`. `introspect`, `exchange` and `assert` share the
same failure convention (nothing on stdout, `"<status>: <reason>"` on stderr) and no fixture, so
one test covers all three; `login` and `rbac` each need a fixture from a different file and get
their own test there.
"""

from __future__ import annotations

import pytest

from kx_auth_cli import cli


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    return code if isinstance(code, int) else 1


def test_human_mode_failure_keeps_stdout_clean_across_commands(monkeypatch, capsys):
    monkeypatch.delenv("KX_AUTH_TOKEN", raising=False)

    # introspect: no token supplied at all
    code = _run(["auth", "introspect"])
    assert code == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("error: no token provided")

    # exchange: rfc_8693 (default strategy) needs a subject and none was supplied
    code = _run(["auth", "exchange", "--audience", "kdbai", "--token-url", "http://x/token"])
    assert code == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("error: strategy 'rfc_8693' needs a subject token")

    # assert: no principal/token supplied
    code = _run(["auth", "assert"])
    assert code == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("error: no principal supplied")
