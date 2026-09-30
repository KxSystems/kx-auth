"""The one output boundary every ``kx`` command runs behind.

The published contract (public/CLAUDE.md, docs/KX_AUTH_CLI.md): every command supports ``--json`` and
prints exactly one envelope on stdout --

    {"status": "ok",     "result": {...}}                       success
    {"status": <status>, "reason": "..."}                       failure
    {"status": "denied", "result": {...}}                       a refusal that carries the decision it made
    {"status": "error",  "result": {...}, "reason": "..."}      ``rbac verify --fail-on``: worked, but unacceptable

-- with ``status`` in ``ok | error | auth_required | denied`` and the exit code ``0`` ok, ``1`` error,
``2`` usage, ``3`` auth-required, ``4`` denied. Without ``--json`` a success prints the result as JSON
(or ``ok`` when there is nothing to return) to stdout and a failure prints ``<status>: <reason>`` to
stderr, so stdout is parseable either way. ``"error"`` is the status for BOTH exit 1 and exit 2: the
code, not the text, is what a caller branches on.

A command expresses an outcome by returning its result or raising a :class:`CliError`; :func:`guarded`
turns either into the envelope and the exit code. Nothing else in the package prints an envelope and no
command holds its own exit constants, so a new command cannot get the contract wrong by construction.
Stdlib only, so the base install stays fastmcp-free.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH_REQUIRED = 3
EXIT_DENIED = 4


class CliError(Exception):
    """A failure the command has classified. The base class IS the operational error (exit 1).

    ``result`` lets a refusal carry the decision it made: ``rbac check`` answers a denial with the
    engine's own ``{"allowed": false, ...}`` and ``verify --fail-on`` fails a pipeline while still
    reporting its findings, so the envelope loses nothing a caller could act on.
    """

    status = "error"
    exit_code = EXIT_ERROR

    def __init__(self, reason: str | None = None, *, result: Any = None) -> None:
        # Exception(None) stringifies as "None"; a reason-less refusal must read as "" instead.
        super().__init__(*(() if reason is None else (reason,)))
        self.reason = reason
        self.result = result


class UsageError(CliError):
    """A value the CALLER typed is unusable (exit 2). Same "error" status as an operational failure:
    the envelope does not distinguish the two, the exit code does. Deliberately NOT a ValueError, so
    "usage" can only ever come from a site that classified it as such — a bare ValueError from a
    dependency (the outbound seam raises one for a misconfiguration) is an operational error."""

    exit_code = EXIT_USAGE


class AuthRequired(CliError):
    """No usable credential, or an expired one (exit 3)."""

    status = "auth_required"
    exit_code = EXIT_AUTH_REQUIRED


class Denied(CliError):
    """A valid caller was refused by policy (exit 4)."""

    status = "denied"
    exit_code = EXIT_DENIED


def json_parent() -> argparse.ArgumentParser:
    """The single ``--json`` declaration; every leaf parser takes it via ``parents=``."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true", help="Emit the stable JSON envelope (the agent path).")
    return parent


def note(text: str) -> None:
    """An advisory for a human (a shadowed $KX_AUTH_TOKEN, login's device-code prompt). Always stderr,
    so a ``--json`` stdout stays exactly one envelope."""
    print(text, file=sys.stderr)


def emit(
    args: argparse.Namespace,
    status: str,
    *,
    result: Any = None,
    reason: str | None = None,
    human: Callable[[Any], str] | None = None,
) -> None:
    """Print the one envelope (``--json``) or its human rendering.

    ``human`` renders a SUCCESS for a terminal; the default is the result as JSON. A command supplies
    one when the bare result is the wrong thing to show a terminal: ``exchange``'s result holds a
    bearer that must not reach a CI log or a shell history file.
    """
    if args.json:
        envelope: dict[str, Any] = {"status": status}
        if result is not None:
            envelope["result"] = result
        if reason is not None:
            envelope["reason"] = reason
        print(json.dumps(envelope, indent=2, default=str))
    elif status == "ok":
        if human is not None:
            print(human(result))
        elif result is not None:
            print(json.dumps(result, indent=2, default=str))
        else:
            print("ok")
    else:
        print(status if reason is None else f"{status}: {reason}", file=sys.stderr)


def guarded(
    args: argparse.Namespace,
    fn: Callable[[], Any],
    *,
    human: Callable[[Any], str] | None = None,
) -> int:
    """Run one command body and own its envelope and exit code.

    ``fn`` returns the success result (``None`` for a bare ``ok``) or raises a :class:`CliError`.
    Anything else it raises is an operational error: the contract is one envelope and a documented
    code, never a traceback, so the residue lands here rather than in ``cli.main``, which cannot know a
    command's shape or code.
    """
    try:
        result = fn()
    except CliError as exc:
        emit(args, exc.status, result=exc.result, reason=exc.reason)
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 -- the boundary is the point
        emit(args, "error", reason=f"{type(exc).__name__}: {exc}")
        return EXIT_ERROR
    emit(args, "ok", result=result, human=human)
    return EXIT_OK
