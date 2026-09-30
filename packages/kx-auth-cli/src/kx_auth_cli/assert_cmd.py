"""``kx auth assert`` — exercise the kdb+ identity-assertion handshake from a shell.

plain kdb+ has no bearer over qIPC, so a caller does not mint a token for it — it **asserts** the
end user's identity: projects the validated claims into a q dict and binds them to a trusted
service-account connection via ``.kx.auth.bind[principal]``. This command runs that handshake
end-to-end from a shell, so an operator, a CI step or an agent can drive a kdb+ target's ``kx.auth``
module and confirm its policy behaves as expected for a given principal.

The target must hold an ``assert`` grant on ``kx.identity`` for the login this command connects as —
``bind`` consults the same default-deny policy it protects, so an ungranted service account is
refused. (A kdb+ running an older ``kx.auth`` gates on the pre-rename bare ``identity`` resource
instead; ``bind`` is called positionally, so this command works against either.)

Two modes:

- **project-only** (no ``--connect``): build and print the principal wire-dict that *would* be bound.
  Uses the shared, fastmcp-free projection — always available, no PyKX needed. Note groups and tenant
  are **not** derived here: q's ``.kx.auth.promote`` is the single promotion authority, so this is an
  indicative preview of the ferry dict, not the promoted principal a policy sees.
- **handshake** (``--connect host:port``): connect as the service account, call ``.kx.auth.bind``,
  then read back ``.kx.auth.valid[]`` and ``.kx.auth.current[]`` (and optionally run a ``--probe``
  query) to confirm the assertion took. The ``current[]`` readback is the point of a handshake over a
  projection: it is the **promoted** principal, with ``groups``/``tenant`` resolved q-side from the
  host's configured claim paths, which the projection cannot show. It is best-effort — a target that
  binds and validates is working, so a readback that will not render does not fail the handshake. The
  qIPC leg needs PyKX, pulled in via the optional ``kx-auth-cli[qipc]`` extra so the base CLI stays
  light + fastmcp-free.

Claims source (first found wins): ``--principal`` JSON (``-`` for stdin, ``@file`` for a file) →
``--token`` (a JWT, decoded **unverified** — this is a local handshake exerciser, not a validator) →
``$KX_AUTH_TOKEN`` (as a JWT). Exit codes: ``0`` ok · ``1`` error (including a principal q refuses as
malformed) · ``2`` usage · ``4`` denied (the target refused the bind — the login lacks ``assert`` on
``kx.identity`` — or a ``--probe`` query was refused by the q-side permission check).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from kx_auth_core import decode_claims_unverified, project_from_claims

from . import atomic, qbridge
from .envelope import CliError, Denied, UsageError, guarded

HELP_DESCRIPTION = (
    "Exercise the kdb+ identity-assertion handshake: project a principal into the q wire-dict and "
    "(with --connect) bind it on a service-account connection to verify a target's kx.auth module."
)
HELP_EPILOG = """\
exit codes (branch on the code, not the text):
  0  ok             projected (project-only), or connected + bound + asserted
  1  error          bad claims, a principal q rejects as malformed, target missing .kx.auth, connect
                    failure, or PyKX not installed
  2  usage          no principal/claims supplied, or a bad --connect value
  3  auth-required  not produced by assert; listed so every command shows the same five codes
  4  denied         the target refused the bind (no `assert on `kx.identity for the login), or a
                    --probe query was refused by the q-side permission check

claims source (first found wins):  --principal JSON  ->  --token JWT  ->  $KX_AUTH_TOKEN (JWT)
  --principal '-'        read JSON claims from stdin
  --principal @file.json read JSON claims from a file

examples:
  # project-only: see exactly what would be bound (no kdb+, no PyKX)
  kx auth assert --principal '{"sub":"alice","scope":"kdbx.read","aud":"kx-mcp"}' --json

  # full handshake against a kdb+ carrying the kx.auth module (needs kx-auth-cli[qipc])
  kx auth assert --token "$TOK" --connect localhost:5010 \\
    --user kxmcp --password "$SVC_PW" --probe "select from trades" --json
"""

# q's stable prefix for a principal that will not promote (modules/kx/auth/init.q, shapeFault).
_MALFORMED = "kx.auth: malformed principal"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--principal", help="Principal claims as JSON ('-' for stdin, '@file' for a file).")
    parser.add_argument("--token", help="A JWT to decode (UNVERIFIED) into claims — convenience for a local handshake.")
    parser.add_argument("--connect", metavar="HOST:PORT", help="kdb+ target to run the bind handshake against (needs the [qipc] extra).")
    parser.add_argument("--user", default=os.environ.get("KX_AUTH_KDB_USER", ""), help="Service-account user for the qIPC login (or $KX_AUTH_KDB_USER).")
    parser.add_argument(
        "--password",
        default=os.environ.get("KX_AUTH_KDB_PASSWORD"),
        help="Service-account password (or $KX_AUTH_KDB_PASSWORD — preferred, keeps it out of shell history).",
    )
    parser.add_argument("--tls", action="store_true", help="Use TLS for the qIPC connection.")
    parser.add_argument("--probe", help="Optional q expression to run after binding (a denial maps to exit 4).")
    parser.add_argument(
        "--promoted-out",
        metavar="FILE",
        help="Atomically write q's promoted principal as JSON (requires --connect).",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="qIPC connection timeout, seconds.")


def _resolve_claims(args: argparse.Namespace) -> dict:
    """The claims to project. Source: --principal JSON, then --token, then $KX_AUTH_TOKEN.

    Two kinds of failure, two exit codes: claims that arrived but do not parse are an error (1), while
    a source that yielded nothing readable is a usage error (2) — the caller has not supplied a
    principal yet.
    """
    if args.principal:
        raw = args.principal
        if raw == "-":
            # An interactive stdin would block, and a broken one raises — the same guard
            # `introspect` and `exchange` put on their own stdin fallbacks.
            try:
                raw = "" if sys.stdin.isatty() else sys.stdin.read()
            except (OSError, ValueError) as exc:
                raise UsageError(f"cannot read the principal from stdin: {exc}") from exc
            if not raw.strip():
                raise UsageError("no principal supplied: nothing readable on stdin")
        elif raw.startswith("@"):
            try:
                with open(raw[1:], "r") as fh:
                    raw = fh.read()
            except OSError as exc:
                raise CliError(f"cannot read principal file: {exc}") from exc
        try:
            claims = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CliError(f"--principal is not valid JSON: {exc}") from exc
        if not isinstance(claims, dict):
            raise CliError("--principal JSON must be an object of claims")
        return claims

    token = args.token or os.environ.get("KX_AUTH_TOKEN")
    if token:
        claims = decode_claims_unverified(token.strip())
        if not claims:
            raise CliError("--token did not decode to any claims (opaque or malformed JWT)")
        return claims

    raise UsageError("no principal supplied (pass --principal JSON, --token JWT, or $KX_AUTH_TOKEN)")


def _charvec(obj, kx):
    """Recursively wrap str leaves as q char vectors, so PyKX does not auto-symbolise them.

    Applied to the raw ``claims`` blob before binding. PyKX maps a Python ``str`` to a q **symbol**,
    and q symbols are never garbage-collected — so ferrying high-cardinality claim values (``jti`` is
    unique per token) as plain strings grows the target's symbol table without bound. As char vectors
    they never intern. This mirrors what a KX MCP server does on the same path, and it is why
    ``.kx.auth.promote`` symbolises only the *promoted* fields it extracts and leaves ``claims`` alone.
    """
    if isinstance(obj, str):
        return kx.CharVector(obj)
    if isinstance(obj, dict):
        return {k: _charvec(v, kx) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_charvec(v, kx) for v in obj]
    return obj


def _bind_failure(exc: Exception) -> CliError:
    """Classify a `.kx.auth.bind` failure.

    q names two refusals of the caller's input — the assert gate ("denied: ...") and a principal that
    will not promote ("kx.auth: malformed principal: ...") — and both are reported verbatim under their
    own exit code. Only an unnamed failure gets the "is kx.auth even loaded?" hint: on a target without
    the module `bind` is undefined, and the raw q error alone is not actionable.
    """
    message = str(exc).strip()
    if message.lower().startswith("denied"):
        return Denied(message)
    if message.startswith(_MALFORMED):
        return CliError(message)
    return CliError(f"bind failed (target missing the kx.auth module?): {exc}")


def _handshake(args: argparse.Namespace, wire: dict) -> dict:
    """Connect as the service account, bind the principal, confirm, optionally probe."""
    try:
        kx = qbridge.import_pykx()
    except Exception as exc:
        raise CliError(
            "PyKX is required for --connect; install the qIPC extra: pip install 'kx-auth-cli[qipc]'"
        ) from exc

    host, _, port = args.connect.partition(":")
    if not port.isdigit():
        raise UsageError("--connect must be HOST:PORT")

    try:
        conn = kx.SyncQConnection(
            host=host or "localhost",
            port=int(port),
            username=args.user,
            password=args.password or "",
            timeout=args.timeout,
            tls=args.tls,
        )
    except Exception as exc:
        raise CliError(f"connect failed: {exc}") from exc

    # Only `claims` is wrapped: the promoted top-level fields are meant to arrive as symbols, which
    # is what q's promote expects of them, and they are low-cardinality by construction.
    ferry = dict(wire)
    if "claims" in ferry:
        ferry["claims"] = _charvec(ferry["claims"], kx)

    try:
        conn(".kx.auth.bind", ferry)
    except Exception as exc:
        raise _bind_failure(exc) from exc

    try:
        bound_valid = bool(conn(".kx.auth.valid[]").py())
    except Exception as exc:
        raise CliError(f"could not read .kx.auth.valid[]: {exc}") from exc

    # Read back the PROMOTED principal, which is the whole reason a handshake beats a projection: it
    # is q's answer, with `groups`/`tenant` resolved by .kx.auth.promote from whatever claim paths the
    # host configured. The projection printed without --connect cannot show any of that. Best-effort —
    # a target that binds and validates is working, so failing to render the readback must not turn a
    # successful handshake into an error.
    promoted = None
    try:
        promoted = qbridge.readable(conn(".kx.auth.current[]").py())
    except Exception:
        promoted = None

    if args.promoted_out:
        if not isinstance(promoted, dict):
            raise CliError("--promoted-out requires a readable .kx.auth.current[] principal")
        try:
            # PRIVATE, like the login cache: this file is not a credential — it never authenticates a
            # mutation — but it carries an identity's promoted attributes and its ferried claims, and
            # the documented handoff (`assert --promoted-out` into `rbac check --principal @FILE`) is
            # one user in one session. Nothing in that flow needs the process umask's wider audience.
            atomic.write_json(Path(args.promoted_out), promoted, mode=atomic.PRIVATE, newline=True)
        except OSError as exc:
            raise CliError(f"cannot write --promoted-out: {exc}") from exc

    result: dict[str, Any] = {"principal": wire, "bound": True, "valid": bound_valid, "probed": bool(args.probe)}
    if promoted is not None:
        result["promoted"] = promoted

    if args.probe:
        try:
            conn(args.probe)
        except Exception as exc:
            if str(exc).strip().lower().startswith("denied"):
                # The bind itself succeeded, so the handshake result rides along with the refusal.
                raise Denied(str(exc), result=result) from exc
            raise CliError(f"probe failed: {exc}") from exc

    return result


def _human(result: dict) -> str:
    # `promoted` is q's own view of the bound principal, so it is a dict rather than a scalar — kept
    # out of the one-line summary and printed under it.
    line = f"ok — principal sub={result['principal'].get('sub')!r}"
    flags = {k: v for k, v in result.items() if k not in ("principal", "promoted")}
    if flags:
        line += " " + " ".join(f"{k}={v}" for k, v in flags.items())
    if "promoted" in result:
        line += f"\n  promoted by q: {result['promoted']}"
    return line


def run(args: argparse.Namespace) -> int:
    def fn() -> dict:
        if args.promoted_out and not args.connect:
            raise UsageError("--promoted-out requires --connect")
        wire = project_from_claims(_resolve_claims(args))
        if not args.connect:
            return {"principal": wire}
        return _handshake(args, wire)

    return guarded(args, fn, human=_human)
