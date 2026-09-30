"""``kx auth login`` — acquire a bearer for an MCP server via server-advertised device-code OAuth.

The mediation model the MCP spec mandates (see ``discovery``): point ``kx auth`` at the **MCP server
(the resource server)** you connect to — *not* a backend. That server publishes RFC 9728 metadata
naming its authorization server; ``kx auth`` discovers the AS and runs the **RFC 8628 device-code**
flow directly against it (never redirecting through the resource server). The token is audienced to
the MCP-server resource; backend-scoped tokens come from a separate ``kx auth exchange``.

Client identity is **DCR-first**: when the AS advertises a ``registration_endpoint`` and no
``--client-id`` is given, register dynamically (RFC 7591) so the user never hand-configures a
client-id; ``--client-id`` / ``$KX_AUTH_CLIENT_ID`` overrides. The acquired credential is written to
the endpoint-keyed token cache for ``kx auth exchange`` to chain off.
"""

from __future__ import annotations

import argparse
import os
import time

import httpx

from . import cache, discovery
from .discovery import DeviceAuthError, DiscoveryError
from .envelope import AuthRequired, CliError, Denied, guarded, note

# DeviceAuthError.reason → how the refusal is classified (anything unlisted is a plain error).
_DEVICE_FAILURES = {
    "access_denied": Denied,
    "expired_token": AuthRequired,
    "timeout": AuthRequired,
}

HELP_DESCRIPTION = (
    "Acquire a bearer for an MCP server via the device-code flow against the authorization server "
    "the server advertises (RFC 9728 discovery → RFC 8628). Caches the token for `exchange`."
)
HELP_EPILOG = """\
exit codes (branch on the code, not the text):
  0  ok             a token was acquired and cached
  1  error          discovery failed, unreachable endpoint, no device-code support, or DCR failure
  2  usage          bad flags
  3  auth-required  the device code expired / timed out before approval — retry
  4  denied         the user denied the authorization request

--server is the MCP-server (resource) URL you connect to — NOT a backend. The client talks directly
to the discovered authorization server; the token is audienced to that resource. Use `kx auth
exchange` for backend-scoped tokens.

client identity (DCR-first):  RFC 7591 dynamic registration if the AS supports it, else --client-id
                              (or $KX_AUTH_CLIENT_ID).

examples:
  kx auth login --server https://mcp.example --json
  kx auth login --server https://mcp.example --client-id my-public-client --scope "kdbx.read offline_access"
"""


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--server", required=True, help="MCP-server (resource) URL to authenticate to.")
    parser.add_argument("--client-id", help="OAuth client id (overrides DCR; falls back to $KX_AUTH_CLIENT_ID).")
    parser.add_argument(
        "--scope", action="append", metavar="SCOPE",
        help="Requested scope; repeatable, or comma/space-separated within one value.",
    )
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification (dev IdPs).")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout, seconds.")


def _scopes(args: argparse.Namespace) -> list[str] | None:
    if not args.scope:
        return None
    out: list[str] = []
    for chunk in args.scope:
        out.extend(part for part in chunk.replace(",", " ").split() if part)
    return out or None


def _prompt(device: dict) -> None:
    """Show the user where to approve — to stderr, so a --json stdout stays clean."""
    complete = device.get("verification_uri_complete")
    uri = device.get("verification_uri", "<unknown>")
    code = device.get("user_code", "<unknown>")
    if complete:
        note(f"To authorize, open: {complete}")
    note(f"To authorize, visit {uri} and enter code: {code}")


def _acquire(args: argparse.Namespace) -> dict:
    """The flow itself: discover, register, device-authorize, poll, cache. Returns the result."""
    scopes = _scopes(args)
    client_id = args.client_id or os.environ.get("KX_AUTH_CLIENT_ID")
    with httpx.Client(verify=not args.no_verify, timeout=args.timeout) as client:
        meta = discovery.discover(args.server, client=client)
        if not client_id:
            client_id = discovery.register_client(
                meta, client=client, client_name="kx-auth-cli", scopes=scopes
            )
        device = discovery.start_device_authorization(meta, client_id, client=client, scopes=scopes)
        _prompt(device)
        token = discovery.poll_for_token(
            meta,
            client_id,
            device["device_code"],
            client=client,
            interval=int(device.get("interval", 5)),
            expires_in=int(device.get("expires_in", 600)),
        )

    expires_in = token.get("expires_in")
    now = int(time.time())
    credential = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "token_type": token.get("token_type", "Bearer"),
        "scope": token.get("scope"),
        "expires_at": now + int(expires_in) if expires_in else None,
        "issued_at": now,
        "authorization_server": meta.authorization_server,
    }
    cache_path = cache.save(args.server, credential)
    return {
        "server": args.server,
        "authorization_server": meta.authorization_server,
        "access_token": token["access_token"],
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": expires_in,
        "cached": True,
        "cache_path": str(cache_path),
    }


def _human(result: dict) -> str:
    return f"ok — logged in to {result['server']} (cached at {result['cache_path']})"


def run(args: argparse.Namespace) -> int:
    def fn() -> dict:
        try:
            return _acquire(args)
        except DiscoveryError as exc:
            raise CliError(str(exc)) from exc
        except DeviceAuthError as exc:
            raise _DEVICE_FAILURES.get(exc.reason, CliError)(str(exc)) from exc
        # httpx.InvalidURL does NOT subclass httpx.HTTPError. `discovery` rejects a malformed URL as
        # a DiscoveryError before httpx sees it, but the exit-code contract is owned here, so this
        # layer does not depend on that holding.
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise CliError(f"network error talking to the authorization server: {exc}") from exc
        # Anything else — a token response missing `access_token`, a non-numeric `expires_in`, an
        # unwritable cache — is the residue `guarded` files as an operational error.

    return guarded(args, fn, human=_human)
