# kx-auth-cli — the `kx auth` CLI

The client-side auth CLI for kdb+ identity assertion, and the OAuth-aware half of the
[`kx.auth`](../../modules/kx/auth/) story. The q module does no token parsing and no crypto, on purpose,
so acquiring a bearer, exchanging it for a backend-scoped one, and projecting it into a principal all
happen out here. `assert` binds the result onto a kdb+ process over qIPC.

It ships the `kx` console script with `auth` and `rbac` command groups.

| Command | What it does | Needs |
|---|---|---|
| `auth login` | Acquire a bearer: RFC 9728 discovery, then RFC 8628 device code. | a resource server |
| `auth exchange` | Swap any subject token for a backend-scoped one (RFC 8693). | a token endpoint |
| `auth assert` | Project a principal; with `--connect`, run the live `.kx.auth.bind` handshake. | a q host running `kx.auth` |
| `auth introspect` | Validate a bearer: issuer, audience, signature, expiry, scopes. | a JWKS URI or public key |
| `rbac …` | Inspect, test and atomically administer policy. | a q host running `kx.rbac` |

**Full command reference: [KX_AUTH_CLI.md](../../docs/KX_AUTH_CLI.md).** Flags, output envelopes,
credential precedence, the gateway route table and the environment variables all live there.

It runs where the client runs, not where kdb+ runs, so it depends on the lean `kx-auth-core` plus
`httpx` and never on `fastmcp`.

## Install

```bash
uv tool install kx-auth-cli          # or: pipx install kx-auth-cli
kx auth --help
```

Add the `qipc` extra for the live `assert --connect` handshake, which needs PyKX:

```bash
uv tool install 'kx-auth-cli[qipc]'
```

### Run without installing (`uvx`)

The `kx` console script is the whole entry point, and `uvx` runs it from the published wheel in an
ephemeral environment:

```bash
uvx --from kx-auth-cli kx auth --help
```

`--from kx-auth-cli` names the package that owns the `kx` command, since `uvx` can't infer it from the
executable name. Add the `qipc` extra the same way: `--from 'kx-auth-cli[qipc]'`. To pin a version, use
`--from kx-auth-cli==<X.Y.Z>`. The CLI shares its version number with the q modules' releases.

## Exit codes

Stable across every subcommand. Branch on the code, not the text.

| Code | Meaning |
|---|---|
| `0` | ok, allowed |
| `1` | error |
| `2` | usage |
| `3` | auth-required |
| `4` | denied |

Every subcommand supports `--json`, which emits exactly one envelope: `{"status": …, "result": …}` on
success, `{"status": …, "reason": …}` on failure — and a `denied` decision or a tripped `--fail-on`
carries `result` too. Every command's payload lives under `result`; all five share one emitter
(`kx_auth_cli/envelope.py`), so none can drift from the shape or the exit table.

Which input earns which code is documented per command in
[`docs/KX_AUTH_CLI.md`](../../docs/KX_AUTH_CLI.md) — as a rule of thumb, a malformed *document* (a
`--principal` file, a server's response) is an error (`1`), while a malformed *flag value* (`--ctx`, an
unknown `--strategy`) is usage (`2`).

## Development

```bash
uv pip install -e '.[qipc]' --group dev
pytest
```

The suite is hermetic: no live IdP, no Keycloak, no kdb+. `login`'s tests stand up an in-process mock
authorization server, and `assert --connect`'s inject a fake `pykx`. Tokens are minted with PyJWT while
`kx-auth-core` verifies with joserfc, which is deliberate cross-library coverage.

Because it fakes `pykx`, **no test here proves the qIPC handshake works against real kdb+.** That is
[`demos/local-assertion/cli-check.sh`](../../demos/local-assertion/cli-check.sh), which drives a live
demo host with this CLI. Install the `[qipc]` extra and `bash demos/local-assertion/run.sh` picks it up.
Run both when you touch `assert`.

### The fastmcp-free invariant

This CLI ships light: `kx-auth-core` and `httpx` only, and it must never import `fastmcp`. Three things
hold the line.

- `introspect`'s verifier is the shared `kx_auth_core.verify_token`, so bearer validation has one
  implementation rather than a client-side copy to drift.
- `login`'s discovery, device-code and cache machinery is CLI-local rather than in `kx-auth-core`. A
  server never logs in, and the cache is a client concern.
- PyKX is imported lazily, only on the `--connect` path, and ships in the `qipc` extra.

Pinned by `test_assert_cmd_import_is_fastmcp_free`, which fails if importing the command pulls
`fastmcp` into the process.

`--json` stdout is exactly one envelope, including on the PyKX path. PyKX's Community banner is
suppressed during the lazy import, so consumers should treat any surrounding output as a contract
violation.
