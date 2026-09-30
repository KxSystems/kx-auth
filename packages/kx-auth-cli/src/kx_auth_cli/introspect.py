"""``kx auth introspect`` — decode/validate a bearer against the configured ``KX_MCP_AUTH`` keys.

Reuses the shared :func:`kx_auth_core.verify_token` — the same validation a KX MCP server enforces on
the way in, so a verdict here is the verdict there — and maps its categorised verdict to the stable
exit-code contract:

* ``0`` valid · ``1`` error (malformed / bad signature / unreachable JWKS) · ``2`` usage (no token) ·
  ``3`` auth-required (expired — the agent should ``login``) · ``4`` denied (issuer / audience /
  required-scope mismatch).

Config defaults come from the ``KX_MCP_AUTH*`` environment — the same variables a KX MCP server
reads, so pointing both at one environment checks against one set of keys; the flags below override
per-invocation. ``introspect`` is stateless — it does not touch the token cache. (Server-advertised
RFC 9728 discovery is handled by ``login``.)
"""

from __future__ import annotations

import argparse
import os
import sys

from kx_auth_core import AUTH_REQUIRED, DENIED, AuthSettings, verify_token

from .envelope import AuthRequired, CliError, Denied, UsageError, guarded, note

# CLI help kept separate from the module docstring above: the docstring is RST for code/IDE readers;
# this is clean plaintext for the terminal (and for an agent reading `--help`). RawDescriptionHelpFormatter
# prints the epilog verbatim, so the alignment below is preserved.
HELP_DESCRIPTION = (
    "Validate a bearer token against the same keys a KX MCP server enforces and report a "
    "machine-readable verdict. Stateless — does not touch any token cache."
)
HELP_EPILOG = """\
exit codes (branch on the code, not the text):
  0  ok             valid
  1  error          malformed / bad signature / unreachable JWKS
  2  usage          bad flags, or no token supplied
  3  auth-required  well-signed but expired — re-authenticate (kx auth login)
  4  denied         well-signed but wrong issuer / audience / required scope

token source, most explicit first:  argument  ->  piped stdin  ->  $KX_AUTH_TOKEN
  a pipe outranks $KX_AUTH_TOKEN (same rule as `exchange`); when both are set the pipe is used and a
  note is written to stderr

config comes from the environment (the same vars the container reads); flags override per call:
  --public-key-path   KX_MCP_AUTH_PUBLIC_KEY_PATH   static mode (PEM on disk)
  --public-key        KX_MCP_AUTH_PUBLIC_KEY        static mode (inline PEM)
  --jwks-uri          KX_MCP_AUTH_JWKS_URI          jwks mode (remote endpoint)
  --issuer            KX_MCP_AUTH_ISSUER
  --audience          KX_MCP_AUTH_AUDIENCE
  --algorithm         KX_MCP_AUTH_ALGORITHM         default RS256
  --required-scopes   KX_MCP_AUTH_REQUIRED_SCOPES   comma/space separated

examples:
  # token + key as flags, structured verdict
  kx auth introspect "$TOKEN" --public-key-path key.pub --issuer https://idp --audience my-api --json

  # config + token entirely from the environment (matches the container)
  KX_MCP_AUTH=static KX_MCP_AUTH_PUBLIC_KEY_PATH=key.pub \\
    KX_AUTH_TOKEN="$TOKEN" kx auth introspect --json

  # validate against a live JWKS endpoint, token piped on stdin
  echo "$TOKEN" | kx auth introspect --jwks-uri https://idp/.well-known/jwks.json
"""

# kx_auth_core's verdict categories, minus OK (a success) and ERROR (the default CliError).
_FAILURES = {AUTH_REQUIRED: AuthRequired, DENIED: Denied}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "token",
        nargs="?",
        help="The bearer token to validate. Falls back to piped stdin, then $KX_AUTH_TOKEN.",
    )
    # Verification config — overrides the KX_MCP_AUTH* environment for this invocation.
    parser.add_argument("--jwks-uri", help="Remote JWKS endpoint (selects jwks mode).")
    parser.add_argument("--public-key", help="Inline RS256 public-key PEM (selects static mode).")
    parser.add_argument(
        "--public-key-path", help="Path to an RS256 public-key PEM (selects static mode)."
    )
    parser.add_argument("--issuer", help="Expected `iss` claim.")
    parser.add_argument("--audience", help="Expected `aud` claim.")
    parser.add_argument("--algorithm", help="Signing algorithm to accept (default RS256).")
    parser.add_argument(
        "--required-scopes", help="Comma/space-separated scopes that must be present."
    )


def _resolve_token(args: argparse.Namespace) -> str | None:
    """Resolve the bearer to validate, in order of **explicitness**: argument → piped stdin →
    ``$KX_AUTH_TOKEN``.

    The environment ranks **below** a pipe, matching ``exchange``'s subject resolution — one rule across
    the CLI, since an agent that learns one command's precedence will apply it to the other. It also
    matters more here than it looks: ``introspect`` is the pre-flight ("does the token my gateway will
    forward actually validate?"), so silently reporting a verdict about a *leftover* ``$KX_AUTH_TOKEN``
    instead of the token piped in would answer a question nobody asked, and answer it convincingly.
    """
    if args.token:
        return args.token

    piped: str | None = None
    try:
        if not sys.stdin.isatty():
            piped = sys.stdin.read().strip() or None
    except (OSError, ValueError):
        # stdin unavailable (e.g. captured under a test harness) — treat as "nothing piped".
        piped = None

    env = (os.environ.get("KX_AUTH_TOKEN") or "").strip() or None

    if piped:
        if env and env != piped:
            note("note: validating the piped token; $KX_AUTH_TOKEN is also set and was ignored.")
        return piped
    return env


def _settings_from_args(args: argparse.Namespace) -> AuthSettings:
    """Start from the KX_MCP_AUTH* environment, then apply explicit flag overrides. Key material on
    the CLI selects the mode, so `introspect <token> --public-key-path k.pub` works with no env."""
    overrides: dict = {}
    for flag in ("jwks_uri", "public_key", "public_key_path", "issuer", "audience"):
        value = getattr(args, flag)
        if value is not None:
            overrides[flag] = value
    if args.algorithm:
        overrides["algorithm"] = args.algorithm
    if args.required_scopes:
        overrides["required_scopes"] = args.required_scopes
    if args.public_key or args.public_key_path:
        overrides["mode"] = "static"
    elif args.jwks_uri:
        overrides["mode"] = "jwks"
    return AuthSettings(**overrides)


def _human(result: dict) -> str:
    return f"valid — client_id={result['client_id']} scopes={result['scopes'] or []}"


def run(args: argparse.Namespace) -> int:
    def fn() -> dict:
        token = _resolve_token(args)
        if not token:
            raise UsageError("no token provided (pass as an argument, $KX_AUTH_TOKEN, or via stdin)")
        try:
            verdict = verify_token(token, _settings_from_args(args))
        except Exception as exc:  # config / unexpected failure → error, with the message as it came
            raise CliError(str(exc)) from exc
        if not verdict.valid:
            raise _FAILURES.get(verdict.category, CliError)(verdict.reason)
        return {
            "valid": True,
            "client_id": verdict.client_id,
            "scopes": verdict.scopes,
            "claims": verdict.claims,
        }

    return guarded(args, fn, human=_human)
