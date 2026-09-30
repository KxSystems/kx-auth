"""Shared auth-test fixtures for the CLI suite (RSA keypair, token minting, a mock token endpoint).

Package-local, deliberately. In the KX MCP container — where this package was built — these lived in
a workspace-root `conftest.py` shared with `kx-auth-core`'s tests and the container's own. Here the
CLI is the only Python package, so the fixtures live beside the tests that use them and the suite
runs with nothing above it on the path.

Tokens are minted with **PyJWT** while `kx-auth-core` verifies with **joserfc**: deliberate
cross-library coverage, which is why both are dev deps. Everything is in-process — no live IdP, no
Keycloak, no container, no q.

Only the fixtures the CLI suite consumes are carried: `keypair`, `other_priv`, `mint` and `mock_sts`.
The container's `jwks_uri` fixture served `kx-auth-core`'s verifier tests and stayed behind;
`introspect`'s tests here derive a public-key file from `keypair` instead. `test_login_cli.py` and
`test_cache.py` declare their own local fixtures (`mock_as`, `cache_file`).
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KID = "test-key-1"
ISSUER = "https://issuer.test"
AUDIENCE = "kx-mcp"

_MOCK_STS_SECRET = "test-secret-key-at-least-32-bytes-long!"


def _gen_rsa() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv, pub


@pytest.fixture(scope="session")
def keypair() -> tuple[str, str]:
    """A session RSA keypair as (private PEM, public PEM)."""
    return _gen_rsa()


@pytest.fixture
def other_priv() -> str:
    """A second private key the verifier does NOT trust — for bad-signature cases."""
    priv, _ = _gen_rsa()
    return priv


@pytest.fixture
def mint(keypair):
    """Factory: mint an RS256 bearer. `exp_delta=-10` → expired; pass `priv=other_priv` → bad sig."""
    default_priv, _ = keypair

    def _mint(
        *,
        priv: str | None = None,
        exp_delta: int = 3600,
        scope: str = "kdbx.read",
        client_id: str = "alice",
        aud: str = AUDIENCE,
        iss: str = ISSUER,
        extra_claims: dict | None = None,
    ) -> str:
        now = int(time.time())
        payload = {
            "iss": iss,
            "aud": aud,
            "sub": client_id,
            "client_id": client_id,
            "scope": scope,
            "iat": now,
            "exp": now + exp_delta,
        }
        if extra_claims:
            payload.update(extra_claims)  # e.g. {"groups": [...]} for group-keyed grant tests
        return jwt.encode(payload, priv or default_priv, algorithm="RS256", headers={"kid": KID})

    return _mint


@pytest.fixture
def mock_sts():
    """An in-process OAuth token endpoint, for the `exchange` tests.

    Captures each POST body (form fields + Authorization header) and returns a minted HS256 JWT
    echoing the requested audience. Yields ``(token_url, captured)`` where ``captured`` is a list
    of dicts — one per request — with a ``_authorization`` key for the Authorization header value.
    """
    captured: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            captured.append({**form, "_authorization": self.headers.get("Authorization", "")})
            aud = form.get("audience", "backend")
            token = jwt.encode(
                {"aud": aud, "sub": "svc-account", "jti": "exch-jti-1", "scope": "kdbx.read"},
                _MOCK_STS_SECRET,
                algorithm="HS256",
            )
            payload = json.dumps(
                {"access_token": token, "token_type": "Bearer", "expires_in": 300}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/token", captured
    finally:
        httpd.shutdown()


@pytest.fixture
def piped_stdin(monkeypatch):
    """Returns a callable that makes stdin look like a pipe carrying the given text (isatty False,
    so a command's stdin-fallback reads it rather than skipping it as an interactive terminal)."""
    import io

    def _pipe(text: str) -> None:
        stream = io.StringIO(text)
        stream.isatty = lambda: False  # type: ignore[method-assign]
        monkeypatch.setattr("sys.stdin", stream)

    return _pipe


# The CLI's published output contract, asserted in one place so any test can reach it — not only the
# known-failing ones that first needed it. `KX_AUTH_CLI.md` documents five exit codes and, under `--json`,
# exactly one envelope on stdout. A traceback satisfies neither, which is the specific failure mode
# several open findings share.
EXIT_CODES = (0, 1, 2, 3, 4)


@pytest.fixture
def run_cli():
    """Invoke the CLI the way `console_scripts` does, returning the exit code.

    `cli.main` always ends in `sys.exit(...)`, so anything OTHER than `SystemExit` escaping means the
    command crashed. That is raised as an `AssertionError` naming the escaping exception rather than left
    to propagate, because "it tracebacked" is a result a test wants to assert on, not an error in the test.
    """
    from kx_auth_cli import cli

    def _run(argv: list[str]) -> int:
        try:
            cli.main(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
        except Exception as exc:  # noqa: BLE001 — the crash is the observation
            raise AssertionError(
                f"the CLI tracebacked instead of exiting: {type(exc).__name__}: {exc}"
            ) from exc
        raise AssertionError("cli.main returned without calling sys.exit")

    return _run


@pytest.fixture
def json_envelope(run_cli, capsys):
    """Run argv under `--json` and assert the whole output contract, returning (exit code, envelope).

    `json.loads` doubles as the "exactly one envelope" check: it rejects two concatenated objects, so a
    command that both `print()`s a line and emits an envelope fails here rather than passing a substring
    match.
    """

    def _envelope(argv: list[str]) -> tuple[int, dict]:
        code = run_cli(argv)
        out, err = capsys.readouterr()
        assert code in EXIT_CODES, f"exit {code} is outside the documented set {EXIT_CODES}"
        assert out.strip(), f"a --json run produced no envelope on stdout (stderr: {err.strip()!r})"
        envelope = json.loads(out)
        assert "status" in envelope, f"envelope has no status: {envelope!r}"
        return code, envelope

    return _envelope
