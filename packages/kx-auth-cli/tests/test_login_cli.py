"""`kx auth login` end to end: RFC 9728 discovery → RFC 7591 DCR → RFC 8628 device-code → cache.

A dependency-free in-process mock authorization server (one origin doubling as the resource server's
metadata host and the AS) serves the well-known documents and the device/token/registration
endpoints. Its behaviour is configurable per test (device support, registration support, the token
poll sequence) so we can drive the happy path, the DCR path, denial, and the no-device-support error
without a live IdP or Docker. `discovery.time.sleep` is neutralised so the poll loop is instant.
"""

from __future__ import annotations

import functools
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from kx_auth_cli import cache, cli, discovery


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    code = exc.value.code
    return code if isinstance(code, int) else 1


def _stub_device_flow(monkeypatch, *, token=None, poll_exc=None, save_exc=None):
    """Install the smallest device flow needed to exercise login's error boundary."""
    from kx_auth_cli import login

    monkeypatch.setattr(
        login.discovery,
        "discover",
        lambda *a, **k: {
            "issuer": "https://issuer.test",
            "token_endpoint": "https://issuer.test/t",
        },
    )
    monkeypatch.setattr(login.discovery, "register_client", lambda *a, **k: "cid")
    monkeypatch.setattr(
        login.discovery,
        "start_device_authorization",
        lambda *a, **k: {
            "device_code": "dc",
            "user_code": "UC",
            "verification_uri": "https://issuer.test/device",
            "interval": 1,
            "expires_in": 10,
        },
    )

    def _poll(*_a, **_k):
        if poll_exc is not None:
            raise poll_exc
        return token if token is not None else {"access_token": "at", "expires_in": 600}

    monkeypatch.setattr(login.discovery, "poll_for_token", _poll)

    def _save(*_a, **_k):
        if save_exc is not None:
            raise save_exc
        return "/tmp/creds.json"

    monkeypatch.setattr(login.cache, "save", _save)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("KX_AUTH_CACHE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("KX_AUTH_CLIENT_ID", raising=False)
    # `sleep`/`monotonic` are default ARGUMENTS on poll_for_token, bound to the real time.sleep at
    # def time — monkeypatching the `time` module's attribute afterward does not reach an already-bound
    # default, so this must replace the module-level function `login.py` actually calls.
    monkeypatch.setattr(
        discovery, "poll_for_token", functools.partial(discovery.poll_for_token, sleep=lambda _s: None)
    )


@pytest.fixture
def mock_as():
    """Start a mock AS; returns (base_url, state). Mutate state['behavior'] before invoking login."""
    state = {
        "captured": [],
        "gets": [],
        "behavior": {
            "device": True,
            "registration": True,
            "path_prm": False,  # serve the RFC 9728 path-aware PRM form too
            # (status, body) popped from the front; the last entry repeats.
            # A str body is served raw as text/html (a non-JSON proxy error page).
            "token_responses": [
                (400, {"error": "authorization_pending"}),
                (200, {"access_token": "at-123", "token_type": "Bearer", "expires_in": 600,
                       "refresh_token": "rt-9", "scope": "kdbx.read"}),
            ],
        },
    }
    base_holder: dict = {}

    def _json(handler, status, body):
        if isinstance(body, str):
            payload, ctype = body.encode(), "text/html"
        else:
            payload, ctype = json.dumps(body).encode(), "application/json"
        handler.send_response(status)
        handler.send_header("Content-Type", ctype)
        handler.end_headers()
        handler.wfile.write(payload)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            base = base_holder["base"]
            beh = state["behavior"]
            state["gets"].append(self.path)
            if self.path.endswith("/.well-known/oauth-protected-resource") or (
                beh["path_prm"] and "/.well-known/oauth-protected-resource/" in self.path
            ):
                _json(self, 200, {"resource": base, "authorization_servers": [base]})
            elif self.path.endswith(".well-known/oauth-authorization-server"):
                meta = {"issuer": base, "token_endpoint": f"{base}/token"}
                if beh["device"]:
                    meta["device_authorization_endpoint"] = f"{base}/device"
                if beh["registration"]:
                    meta["registration_endpoint"] = f"{base}/register"
                _json(self, 200, meta)
            else:
                _json(self, 404, {"error": "not_found"})

        def do_POST(self):  # noqa: N802
            base = base_holder["base"]
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            # DCR (RFC 7591) posts JSON; device/token requests post form-encoded. Branching on
            # Content-Type is what makes a captured /register body (e.g. its `scope` field)
            # actually reflect what was sent, instead of parse_qs silently yielding junk.
            if "application/json" in self.headers.get("Content-Type", ""):
                form = json.loads(raw)
            else:
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            self_path = self.path.rstrip("/")
            state["captured"].append({"path": self_path, **form})
            if self_path.endswith("/register"):
                _json(self, 201, {"client_id": "dyn-client-123"})
            elif self_path.endswith("/device"):
                _json(self, 200, {
                    "device_code": "dev-abc", "user_code": "WXYZ-1234",
                    "verification_uri": f"{base}/activate", "interval": 0,
                    "expires_in": state["behavior"].get("expires_in", 600),
                })
            elif self_path.endswith("/token"):
                seq = state["behavior"]["token_responses"]
                status, body = seq[0] if len(seq) == 1 else seq.pop(0)
                _json(self, status, body)
            else:
                _json(self, 404, {"error": "not_found"})

        def log_message(self, *_a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base_holder["base"] = f"http://127.0.0.1:{httpd.server_address[1]}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield base_holder["base"], state
    finally:
        httpd.shutdown()


def test_device_code_happy_path_caches_token(mock_as, capsys):
    base, state = mock_as
    code = _run(["auth", "login", "--server", base, "--json"])
    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "ok"
    assert envelope["result"]["access_token"] == "at-123"
    assert envelope["result"]["cached"] is True
    # the token landed in the endpoint-keyed cache
    entry = cache.get(base)
    assert entry["access_token"] == "at-123"
    assert entry["refresh_token"] == "rt-9"


def test_dcr_registers_a_client_when_no_client_id(mock_as):
    base, state = mock_as
    assert _run(["auth", "login", "--server", base]) == 0
    # DCR happened, and the dynamically-registered client_id was used for device + token calls
    paths = [c["path"] for c in state["captured"]]
    assert any(p.endswith("/register") for p in paths)
    device_calls = [c for c in state["captured"] if c["path"].endswith("/device")]
    assert device_calls and device_calls[0]["client_id"] == "dyn-client-123"


def test_explicit_client_id_skips_dcr(mock_as):
    base, state = mock_as
    assert _run(["auth", "login", "--server", base, "--client-id", "my-public-client"]) == 0
    paths = [c["path"] for c in state["captured"]]
    assert not any(p.endswith("/register") for p in paths)  # --client-id overrides DCR
    device_calls = [c for c in state["captured"] if c["path"].endswith("/device")]
    assert device_calls[0]["client_id"] == "my-public-client"


def test_access_denied_is_denied_4(mock_as, capsys):
    base, state = mock_as
    state["behavior"]["token_responses"] = [(400, {"error": "access_denied"})]
    code = _run(["auth", "login", "--server", base, "--json"])
    assert code == 4
    assert json.loads(capsys.readouterr().out)["status"] == "denied"


def test_human_mode_failure_keeps_stdout_clean(mock_as, capsys):
    base, state = mock_as
    state["behavior"]["token_responses"] = [(400, {"error": "access_denied"})]
    code = _run(["auth", "login", "--server", base])
    assert code == 4
    out, err = capsys.readouterr()
    assert out == ""
    # stderr also carries the device-code prompt (_prompt), which --json suppresses from stdout
    # by design — the failure line is the last one, not the whole of stderr.
    assert err.strip().splitlines()[-1] == "denied: the user denied the authorization request"


def test_real_deadline_expiry_is_a_clean_timeout_3(mock_as, capsys):
    # expires_in=0 makes the deadline already-passed by the time the first response is handled.
    # The check happens BEFORE poll_for_token ever sleeps, so this is a genuine timeout exit with
    # zero wall-clock cost — not the generic access_denied/expired_token paths above.
    base, state = mock_as
    state["behavior"]["expires_in"] = 0
    state["behavior"]["token_responses"] = [(400, {"error": "authorization_pending"})]
    code = _run(["auth", "login", "--server", base, "--json"])
    assert code == 3
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "auth_required"
    assert "timed out" in envelope["reason"]


def test_scope_propagates_to_registration_and_device_but_not_to_poll(mock_as):
    base, state = mock_as
    assert _run(["auth", "login", "--server", base, "--scope", "kdbx.read offline_access"]) == 0
    register_calls = [c for c in state["captured"] if c["path"].endswith("/register")]
    device_calls = [c for c in state["captured"] if c["path"].endswith("/device")]
    token_calls = [c for c in state["captured"] if c["path"].endswith("/token")]
    assert register_calls[0]["scope"] == "kdbx.read offline_access"
    assert device_calls[0]["scope"] == "kdbx.read offline_access"
    assert all("scope" not in c for c in token_calls)  # never forwarded to the poll loop


def test_no_device_support_is_error_1(mock_as, capsys):
    base, state = mock_as
    state["behavior"]["device"] = False
    state["behavior"]["registration"] = False  # force an explicit --client-id path past discovery
    code = _run(["auth", "login", "--server", base, "--client-id", "c1", "--json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_path_mounted_server_uses_path_aware_prm(mock_as):
    base, state = mock_as
    state["behavior"]["path_prm"] = True
    server = f"{base}/mcp"
    assert _run(["auth", "login", "--server", server]) == 0
    # the RFC 9728 path-aware form was tried first, and the cache is keyed by the full server URL
    assert state["gets"][0] == "/.well-known/oauth-protected-resource/mcp"
    assert cache.get(server)["access_token"] == "at-123"


def test_no_registration_endpoint_and_no_client_id_names_the_fix(mock_as, capsys):
    # device flow is supported, but DCR is not, and the caller passed no --client-id: the specific
    # branch this pins is register_client's own message, not the generic no-device-support error
    # test_no_device_support_is_error_1 covers (that one deliberately passes --client-id past it).
    base, state = mock_as
    state["behavior"]["registration"] = False
    code = _run(["auth", "login", "--server", base, "--json"])
    assert code == 1
    envelope = json.loads(capsys.readouterr().out)
    assert "registration_endpoint" in envelope["reason"]
    assert "--client-id" in envelope["reason"]


def test_no_registration_endpoint_but_explicit_client_id_still_works(mock_as):
    # The complement: the same AS, but the caller followed the message's own advice.
    base, state = mock_as
    state["behavior"]["registration"] = False
    assert _run(["auth", "login", "--server", base, "--client-id", "manual-client"]) == 0
    device_calls = [c for c in state["captured"] if c["path"].endswith("/device")]
    assert device_calls[0]["client_id"] == "manual-client"


# --- --no-verify: the single point where it reaches httpx --------------------------------------


def test_no_verify_disables_tls_verification(mock_as, monkeypatch):
    import kx_auth_cli.login as login_module

    captured: dict = {}
    real_client = httpx.Client

    class _SpyClient(real_client):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(login_module.httpx, "Client", _SpyClient)

    base, _ = mock_as
    assert _run(["auth", "login", "--server", base, "--no-verify"]) == 0
    assert captured["verify"] is False


def test_verify_stays_on_by_default(mock_as, monkeypatch):
    import kx_auth_cli.login as login_module

    captured: dict = {}
    real_client = httpx.Client

    class _SpyClient(real_client):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(login_module.httpx, "Client", _SpyClient)

    base, _ = mock_as
    assert _run(["auth", "login", "--server", base]) == 0
    assert captured["verify"] is True


def test_prm_discovery_falls_back_to_origin_root(mock_as):
    base, state = mock_as  # the mock serves only the origin-root PRM form by default
    assert _run(["auth", "login", "--server", f"{base}/mcp"]) == 0
    assert state["gets"][0] == "/.well-known/oauth-protected-resource/mcp"  # tried (404s)...
    assert state["gets"][1] == "/.well-known/oauth-protected-resource"  # ...then the root form


def test_non_json_token_response_is_clean_error_1(mock_as, capsys):
    base, state = mock_as
    state["behavior"]["token_responses"] = [(502, "<html>bad gateway</html>")]
    code = _run(["auth", "login", "--server", base, "--json"])
    assert code == 1  # a clean envelope, not a JSONDecodeError traceback
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_missing_server_is_usage_error_2(capsys):
    # --server is required=True, so this never contacts a server — no mock_as fixture needed.
    code = _run(["auth", "login"])
    assert code == 2
    assert capsys.readouterr().err  # argparse's own usage text, not a JSON envelope


def test_non_numeric_timeout_is_usage_error_2(capsys):
    # --timeout is type=float; argparse rejects the value before any server is contacted.
    code = _run(["auth", "login", "--server", "https://mcp.example", "--timeout", "not-a-number"])
    assert code == 2
    assert capsys.readouterr().err


def test_malformed_server_url_exits_cleanly_instead_of_raising(capsys):
    # A malformed IPv6-shaped host made `_prm_candidates`'s urlsplit raise a bare ValueError, which
    # none of login.py's except clauses caught, so it escaped as a traceback. The envelope assertion
    # is the real contract here: an uncaught exception also exits 1, so the code alone under-specifies
    # this. discovery.py now converts it to a DiscoveryError.
    code = _run(["auth", "login", "--server", "http://[::1", "--json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_a_malformed_authorization_server_url_is_a_clean_discovery_error():
    # The same hole, one layer out and NOT caused by user input: authorization_servers[0] comes from
    # the resource server's own metadata, and urljoin raises a bare ValueError on a malformed one. A
    # broken or hostile server must not be able to crash the CLI.
    def respond(request):
        if "oauth-protected-resource" in request.url.path:
            return httpx.Response(200, json={"authorization_servers": ["http://[::1"]})
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(discovery.DiscoveryError, match="not a usable URL"):
            discovery.discover("https://mcp.example", client=client)


def test_a_malformed_token_endpoint_is_a_clean_discovery_error():
    # Also remote-supplied. httpx.InvalidURL does not subclass httpx.HTTPError, so a malformed
    # token_endpoint used to escape from poll_for_token's un-guarded post. `discover` now rejects it
    # at the boundary, which is why the three functions downstream need no guard of their own.
    def respond(request):
        if "oauth-protected-resource" in request.url.path:
            return httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        if "oauth-authorization-server" in request.url.path:
            return httpx.Response(200, json={"token_endpoint": "http://[::1"})
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(discovery.DiscoveryError, match="token_endpoint is not a usable URL"):
            discovery.discover("https://mcp.example", client=client)


# Regression for finding kx-auth-cli #8 and #1 — login.run's allow-list lets everything else escape
# as a traceback.
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param({"save_exc": OSError(13, "Permission denied")}, id="cache-save-unwritable"),
        pytest.param({"poll_exc": KeyError("boom")}, id="flow-raises-outside-the-allow-list"),
        pytest.param({"token": {"token_type": "Bearer"}}, id="token-response-lacks-access_token"),
        pytest.param(
            {"token": {"access_token": "at", "expires_in": "soon"}},
            id="non-numeric-expires_in",
        ),
    ],
)
def test_login_answers_with_an_envelope_however_the_flow_fails(
    failure, monkeypatch, json_envelope
):
    _stub_device_flow(monkeypatch, **failure)
    code, envelope = json_envelope(
        ["auth", "login", "--server", "https://mcp.test", "--json"]
    )
    assert code != 0, f"a failed login reported success: {envelope!r}"
    assert envelope["status"] == "error", envelope


# --- the envelope shape: {status, result} on success, {status, reason} on failure ------------------


def test_success_nests_the_credential_under_result(mock_as, capsys):
    base, _ = mock_as
    assert _run(["auth", "login", "--server", base, "--json"]) == 0
    env = json.loads(capsys.readouterr().out)
    assert set(env) == {"status", "result"}
    assert set(env["result"]) == {
        "server", "authorization_server", "access_token", "token_type", "expires_in", "cached", "cache_path",
    }


def test_failures_are_status_and_reason_only(monkeypatch, capsys):
    _stub_device_flow(monkeypatch, poll_exc=KeyError("boom"))
    assert _run(["auth", "login", "--server", "https://mcp.test", "--json"]) == 1
    assert set(json.loads(capsys.readouterr().out)) == {"status", "reason"}
