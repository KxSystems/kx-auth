"""``kx auth exchange`` — swap a subject token for a backend-scoped credential (RFC 8693 from a shell).

A thin wrapper over the shared :func:`kx_auth_core.exchange` seam — the *same* outbound code path a
KX MCP server's backends use — so the wire shape and audit chain are one implementation. Default strategy
is ``rfc_8693`` (the workload-identity bootstrap target: ``kubectl create token`` / ``gh
actions-token`` → ``kx auth exchange`` → backend-scoped token); ``passthrough`` / ``service_account``
/ custom registered strategies are selectable too.

Subject-token source, in order of **explicitness** (see ``_resolve_subject``): ``--subject`` → piped
stdin → ``$KX_AUTH_TOKEN`` → the cached ``login`` token for ``--server`` (the seamless ``login`` →
``exchange`` chain). ``service_account`` needs no subject. Maps the seam's result to the stable exit-code contract: ``0`` ok · ``1`` error ·
``2`` usage · ``3`` auth-required (the only subject candidate was an expired ``login`` cache entry) ·
``4`` denied (a ``passthrough`` audience-guard refusal).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from kx_auth_core import OutboundConfig, exchange, outbound_strategies

from . import cache
from .envelope import AuthRequired, CliError, Denied, UsageError, guarded, note

_NEEDS_SUBJECT = {"passthrough", "rfc_8693"}

HELP_DESCRIPTION = (
    "Exchange a subject token for a backend-scoped credential via the shared outbound seam "
    "(one implementation, shared with the server side). Default strategy: rfc_8693."
)
HELP_EPILOG = """\
exit codes (branch on the code, not the text):
  0  ok             a credential was minted/forwarded
  1  error          misconfig, unreachable endpoint, or the endpoint returned no token
  2  usage          bad flags, an unrecognised --strategy, or no subject token for one that needs it
  3  auth-required  the cached login for --server has expired — `kx auth login` again
  4  denied         the strategy refused (e.g. passthrough audience-guard mismatch)

subject source, most explicit first:  --subject  ->  piped stdin  ->  $KX_AUTH_TOKEN  ->  login cache (--server)
  a pipe outranks $KX_AUTH_TOKEN, so a leftover token cannot shadow one you piped in; when both are
  present the pipe is used and a note is written to stderr

strategies:
  rfc_8693         (default) token exchange at --token-url for --audience; needs a subject token
  passthrough      forward the subject unchanged iff its aud already includes --audience
  service_account  client_credentials at --token-url (the caller's own identity; no subject)

examples:
  # RFC 8693 swap (subject as a flag), structured output
  kx auth exchange --subject "$TOK" --audience kdbai \\
    --token-url https://idp/token --client-id mcp-container --client-secret "$SECRET" --json

  # chain off a prior `kx auth login` — subject pulled from the cache for that server
  kx auth login --server https://mcp.example --json
  kx auth exchange --server https://mcp.example --audience backend-api --token-url https://idp/token --json
"""


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subject", help="The subject (inbound) token. Falls back to piped stdin, then $KX_AUTH_TOKEN, then the login cache.")
    parser.add_argument("--audience", help="Target backend audience (the token is scoped to this).")
    parser.add_argument("--strategy", default="rfc_8693", help="Outbound strategy (default rfc_8693).")
    parser.add_argument("--token-url", help="OIDC/STS token endpoint (rfc_8693 / service_account).")
    parser.add_argument("--resource", help="RFC 8707 resource URI — an alternative to --audience.")
    parser.add_argument("--client-id", help="Client id for authenticating at the token endpoint.")
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("KX_AUTH_CLIENT_SECRET"),
        help="Client secret paired with --client-id. Falls back to $KX_AUTH_CLIENT_SECRET "
        "(preferred — keeps the secret out of shell history and process listings).",
    )
    parser.add_argument(
        "--client-auth", choices=("post", "basic"), default="post",
        help="How client credentials reach the token endpoint (default post).",
    )
    parser.add_argument(
        "--scope", action="append", metavar="SCOPE",
        help="Requested scope; repeatable, or comma/space-separated within one value.",
    )
    parser.add_argument("--server", help="MCP-server URL — used to pull the subject from the login cache.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification (dev IdPs).")
    parser.add_argument("--timeout", type=float, default=30.0, help="Token-request timeout, seconds.")


def _resolve_subject(args: argparse.Namespace) -> tuple[str | None, bool]:
    """Resolve the subject token; the second element flags that the only candidate was an
    expired ``login``-cache entry (so the caller can map it to auth-required, not usage).

    Precedence is by **explicitness**, not convenience: an explicit flag, then input piped at *this*
    invocation, then the ambient environment, then the cache.

    ``$KX_AUTH_TOKEN`` deliberately ranks **below** stdin. It is inherited state — very often left over
    from an earlier ``kx auth login``, or from the `exchange` → `assert` handoff itself — and while it
    outranked a piped token, the workload-identity path (`platform token | kx auth exchange`) silently
    exchanged the stale credential instead of the one it was handed. Wrong identity, no error. Ambient
    state must never win over an argument the caller passed on purpose.
    """
    if args.subject:
        return args.subject, False

    # isatty() keeps an interactive run from blocking on a terminal. A non-tty stdin carrying nothing
    # reads as "" (or raises) and falls through to the environment. A caller who inherits an open, idle
    # stdin blocks here — inherent to accepting piped input, and no worse than before this reordering,
    # which only changes WHICH source wins once stdin has actually yielded something.
    piped: str | None = None
    try:
        if not sys.stdin.isatty():
            piped = sys.stdin.read().strip() or None
    except (OSError, ValueError):
        piped = None

    env = (os.environ.get("KX_AUTH_TOKEN") or "").strip() or None

    if piped:
        # Say so rather than resolving the ambiguity silently — on stderr, so a --json envelope on
        # stdout stays machine-parseable (the same split `login` uses for its device-code prompt).
        if env and env != piped:
            note(
                "note: using the piped subject token; $KX_AUTH_TOKEN is also set and was ignored. "
                "Pass --subject to be explicit."
            )
        return piped, False
    if env:
        return env, False

    if args.server:
        entry = cache.get(args.server)
        if entry and entry.get("access_token"):
            expires_at = entry.get("expires_at")
            if expires_at:
                try:
                    expired = time.time() >= float(expires_at)
                except (TypeError, ValueError):
                    # An expiry that will not read is not a usable credential: report it as
                    # auth-required rather than sending a token whose lifetime is unknown.
                    return None, True
                if expired:
                    return None, True
            return entry["access_token"], False
    return None, False


def _scopes(args: argparse.Namespace) -> list[str] | None:
    if not args.scope:
        return None
    out: list[str] = []
    for chunk in args.scope:
        out.extend(part for part in chunk.replace(",", " ").split() if part)
    return out or None


def _config_from_args(args: argparse.Namespace) -> OutboundConfig:
    return OutboundConfig(
        strategy=args.strategy,
        token_url=args.token_url,
        audience=args.audience,
        resource=args.resource,
        client_id=args.client_id,
        client_secret=args.client_secret,
        client_auth=args.client_auth,
        scopes=_scopes(args),
        verify=not args.no_verify,
        timeout=args.timeout,
    )


def _human(result: dict) -> str:
    # No access_token here: this line goes to a terminal, a CI log and a shell history file. Anyone who
    # needs the token itself is already using --json.
    return f"ok — strategy={result['strategy']} token_type={result['token_type']} expires_in={result['expires_in']}"


def run(args: argparse.Namespace) -> int:
    def fn() -> dict:
        # Checked against the registry, never restated here: a typo like "rfc8693" is not in
        # `_NEEDS_SUBJECT` either, so without this it would skip the subject check below and surface as
        # a generic exit-1 failure deep in the outbound seam instead of a usage error naming the typo.
        known = outbound_strategies()
        if args.strategy not in known:
            raise UsageError(f"unknown --strategy {args.strategy!r}; choose one of: {', '.join(sorted(known))}")

        subject, cache_expired = _resolve_subject(args)
        if args.strategy in _NEEDS_SUBJECT and not subject:
            if cache_expired:
                raise AuthRequired(
                    f"the cached login for {args.server} has expired — "
                    f"run `kx auth login --server {args.server}` again"
                )
            raise UsageError(
                f"strategy '{args.strategy}' needs a subject token "
                "(pass --subject, $KX_AUTH_TOKEN, stdin, or --server for the login cache)"
            )

        try:
            credential = asyncio.run(exchange(_config_from_args(args), subject))
        except PermissionError as exc:  # strategy refusal (e.g. passthrough audience guard)
            raise Denied(str(exc)) from exc
        except Exception as exc:  # the seam's ValueError (misconfig / no token), httpx, unexpected
            raise CliError(str(exc)) from exc
        return {
            "access_token": credential.access_token,
            "token_type": credential.token_type,
            "expires_in": credential.expires_in,
            "strategy": credential.strategy,
            "claims": credential.claims,
        }

    return guarded(args, fn, human=_human)
