# `kx auth` CLI reference

The command-line half of the [authorization story](AUTHORIZATION.md). It does two jobs, in two command
groups, and they are less related than sharing a binary suggests.

**`kx auth` gets an identity into q.** The modules parse no tokens and perform no crypto, so acquiring a
bearer, exchanging it for a backend-scoped one, and projecting it into a principal all happen out here.
`assert` binds the result onto a running process and reads back what q promoted it to.

**`kx rbac` administers the policy that decides what an identity may do.** It fronts the `kx.rbac`
engine's own verbs over either transport: read the grant table, test a decision before committing to it,
and change policy as an atomic transaction that persists before it takes effect. No policy logic lives
here. Every semantic belongs to q, and the CLI is a shim that would be wrong to make clever.

The two meet at `kx auth assert --promoted-out`, which hands `kx rbac check --principal` a principal q
itself promoted, so a decision can be modelled against exactly the subject the engine would see.

Installation and the package's own notes are in the
[package README](../packages/kx-auth-cli/README.md).

## Choosing a path

Three of the four `auth` commands work against a bare kdb+ with nothing in front of it. `login` is the
exception, and it is worth understanding why before reaching for it.

kdb+ cannot be the OAuth anchor. Nothing in the data path can publish protected-resource metadata or
validate a bearer, and `login` needs something that does.

| Topology | Commands that carry the weight |
|---|---|
| **Workload or CI to kdb+.** A platform-issued token is exchanged and asserted. No human, no browser, no discovery. | `exchange`, then `assert` |
| **Operator or agent administering a q host** over qIPC. The caller's own kdb+ login is the subject, so there is no IdP round trip. | `rbac --connect`, and `assert` when an asserted identity is needed |
| **A gateway or MCP server in front of kdb+**, the interactive human case. The proxy runs the browser flow and validates the bearer. | `login`, then `rbac --server` |

Without a validator somewhere in the path, an acquired bearer is a claims carrier rather than a
credential. `assert` decodes claims unverified by design and q does no crypto, so the security rests on
the service-account connection plus the target's `assert` grant. Reach for `login` when something
downstream checks the token, not before.

## The exit-code contract

Stable across every subcommand. Branch on the code, not the text.

| Code | Meaning | HTTP analogy |
|---|---|---|
| `0` | ok, allowed | 200 |
| `1` | error: malformed input, unreachable endpoint, unexpected failure | 400/500 |
| `2` | usage: bad flags or a missing required input | |
| `3` | auth-required: no credential, or an expired one | 401 |
| `4` | denied: valid credential, authorization refused | 403 |

## The JSON envelope

With `--json`, every command prints exactly one envelope:

```json
{ "status": "ok", "result": { } }
{ "status": "denied", "reason": "…" }
```

`result` is present on success, and also on a refusal that still has something to report: a `denied`
`check`/`explain` carries the engine's decision, a `denied` `assert --probe` carries the handshake that
succeeded before the probe, and `verify --fail-on` carries its findings beside its `reason`. `reason` is
present on every failure. Every command's payload lives under `result` — none puts fields beside
`status`. Without `--json`, a success prints the bare result to stdout (or `ok` when there is nothing to
return; the four `auth` commands print a one-line summary instead, and `exchange`'s never includes the
token) and a failure prints `status: reason` to **stderr**, so stdout stays parseable either way.

Every `result` names its own fields rather than nesting an anonymous value. `save` returns the store
path it wrote, `load` the number of grants it installed:

```json
{ "status": "ok", "result": { "path": "/etc/kx/grants" } }
{ "status": "ok", "result": { "grants": 12 } }
```

## Credential precedence

It differs per command, and the ordering is deliberate. Explicit beats piped, piped beats inherited.

| Command | Order |
|---|---|
| `introspect` | argument, then piped stdin, then `$KX_AUTH_TOKEN` |
| `exchange` | `--subject`, then piped stdin, then `$KX_AUTH_TOKEN`, then the `login` cache for `--server` |
| `assert` | `--principal`, then `--token`, then `$KX_AUTH_TOKEN` |
| `rbac --server` | `--token`, then `$KX_AUTH_TOKEN`, then the cache entry for that server |
| `rbac --connect` | `--user` / `--password`, else `$KX_AUTH_KDB_USER` / `$KX_AUTH_KDB_PASSWORD` |

The environment ranks below a pipe on purpose. It is usually inherited rather than intended, commonly
left over from an earlier `login`, and if it outranked a pipe the workload-identity path would silently
exchange a stale credential: wrong identity, no error. When both are present the pipe wins and a note
goes to stderr.

## `kx auth introspect`

Validate a bearer against the same keys and the same verifier a KX MCP server enforces, so a verdict
here is the verdict there. Stateless, and it never touches the token cache.

```bash
kx auth introspect "$TOKEN" --public-key-path key.pub \
  --issuer https://idp --audience my-api --json

echo "$TOKEN" | kx auth introspect --jwks-uri https://idp/.well-known/jwks.json
```

Verification config defaults from the `KX_MCP_AUTH*` environment, the same variables a KX MCP server
reads. Flags override per call: `--jwks-uri`, `--public-key`, `--public-key-path`, `--issuer`,
`--audience`, `--algorithm`, `--required-scopes`.

Result: `result` carries `{valid: true, client_id, scopes, claims}`. A failure is `{status, reason}` with no
`result`; `status` alone says why the token did not validate.

## `kx auth login`

Acquire a bearer through the device-code flow, against the authorization server the resource server
advertises. You never hand-configure a realm, client id or AS URL.

`--server` is the resource URL you connect to, not a backend. It must publish
[RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) metadata naming its authorization server;
`kx auth` discovers the AS and runs the [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) device-code
flow directly against it. A plain kdb+ cannot be that server, so in a bare deployment use the
workload-identity path with `exchange` instead, or put a gateway in front.

There is deliberately no flag to skip discovery and point straight at an authorization server. It would
let you mint a bearer that nothing in your deployment validates, which invites reading a token as proof
that kdb+ checked something. kdb+ never does.

Client identity is DCR-first: where the AS advertises a `registration_endpoint` the client registers
dynamically ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)). `--client-id` or
`$KX_AUTH_CLIENT_ID` overrides.

```bash
kx auth login --server https://mcp.example --json
kx auth login --server https://mcp.example --scope "kdbx.read offline_access"
```

The approval prompt goes to **stderr**, so a `--json` result on stdout stays clean. Device-code is the
only flow implemented.

Result: `result` carries `{server, authorization_server, access_token, token_type, expires_in, cached,
cache_path}`. The human-readable line names the server and the cache path and never prints the token.

Exits: `1` discovery, network or DCR failure. `3` the device code expired before approval. `4` the user
denied the request.

## `kx auth exchange`

Swap a subject token for a backend-scoped credential, through the same outbound seam a KX MCP server's
backends use, so the wire shape and audit chain are one implementation.

This is the workload-identity bootstrap and the shortest path from a platform token to an asserted
principal. Nothing is discovered and no human is involved.

```bash
export KX_AUTH_TOKEN="$(kubectl create token ingest-sa \
  | kx auth exchange --audience kdbx --token-url https://idp/token --json \
  | jq -r .result.access_token)"

kx auth assert --connect kdb:5010 --user svcuser \
  --probe '.kx.auth.authorize[`write;`data.trades]' --json
```

The `jq` in the middle is not incidental. `exchange` emits an envelope with the token at
`result.access_token`, while `assert` reads a token from `--token` or `$KX_AUTH_TOKEN`, and its stdin
form expects *claims* JSON rather than a token. Extract the token between the two.

Default strategy is `rfc_8693`. `passthrough` and `service_account` are selectable with `--strategy`,
and `service_account` needs no subject.

Result: `result` carries `{access_token, token_type, expires_in, strategy, claims}`.

Exits: `1` misconfiguration, unreachable endpoint, or no token returned. `2` no subject for a strategy
that needs one, **or an unrecognised `--strategy`** (checked against `kx-auth-core`'s own registry).
`3` the cached login has expired, or its cached `expires_at` could not be read. `4` the strategy refused.

## `kx auth assert`

Inspect the projection sent to kdb+, or run the full handshake against a live process. This is what
makes a kdb+ running `kx.auth` drivable from a shell with no MCP server in the path.

Without `--connect` it projects claims into the principal wire format and prints them, needing neither
kdb+ nor PyKX. With `--connect HOST:PORT` it logs in over qIPC as the service account, calls
`.kx.auth.bind`, checks `valid[]`, reads back `current[]`, and optionally runs a `--probe` expression.

The readback is the point of a handshake over a projection. It returns the **promoted** principal, with
groups and tenant resolved q-side, as `result.promoted`. It is best-effort: a target that binds and
validates is working, so a readback that will not render does not fail the handshake.

Groups and tenant are never derived here. `.kx.auth.promote` is the single promotion authority, so
`result.principal` is an indicative preview of the ferry payload, not what a policy sees. A principal q
refuses as malformed (`kx.auth: malformed principal: …`) is reported verbatim, exit `1`.

Result: `result` carries `{principal}` for a projection and `{principal, bound, valid, probed[, promoted]}`
after a handshake. A `--probe` denial keeps that `result` beside its `reason`: the bind itself succeeded.

The target must grant the connecting login `assert` on `kx.identity`. JWT claims are decoded **without
verification**; this is a projection and handshake diagnostic, not a substitute for `introspect`.

```bash
kx auth assert --principal '{"sub":"alice","aud":"kx-mcp"}' --json

kx auth assert --token "$TOK" --connect localhost:5010 --user svcuser \
  --probe ".kx.auth.authorize[\`read;\`data.trades]" --json
```

`--promoted-out FILE` (with `--connect`) atomically writes q's promoted principal as clean JSON, which
makes a decision chain explicit:

```bash
kx auth assert --token "$TOK" --connect localhost:5010 --promoted-out principal.json --json
kx rbac check read:data.trades --principal @principal.json --connect localhost:5010 --json
```

That file is policy input, not a credential. It can answer `check` and `explain`; it cannot authenticate
a mutation. It is still written `0600`: it carries the identity's promoted attributes and its ferried
claims, and the handoff above is one user in one session, so there is nothing for the process umask's
wider audience to do.

Prefer `$KX_AUTH_KDB_PASSWORD` over `--password`, so the service-account password stays out of shell
history and process listings.

Exits: `1` invalid claims (including a principal q refuses as malformed), connection or module error.
`2` missing input or a bad `--connect` value. `4` the target refused the bind — the connecting login
lacks `assert` on `kx.identity` — or the probe was denied by q-side policy.

## `kx rbac`

Inspect, test and atomically administer the `kx.rbac` engine. Grant visibility and pure `check` and
`explain` decisions are public within the chosen transport. The q module, not the CLI, requires
`admin` on `kx.rbac` for mutations and persistence.

A transport is required on every subcommand, and the two are mutually exclusive.

```bash
# qIPC: the caller's kdb+ login is the subject
kx rbac show --connect localhost:5010 --json
kx rbac grant trader read:data.trades --connect localhost:5010 --json

# gateway: a prior login supplies the cached bearer
kx auth login --server https://gateway.example
kx rbac revoke trader write:data.trades --server https://gateway.example --json
```

`--connect HOST:PORT` uses qIPC and needs the `qipc` extra. `--server URL` calls fixed routes under
`/kx/rbac/v1`, where the gateway's validated request principal is the decision subject and always
authenticates mutations.

| Verb | Method and route |
|---|---|
| `show` | `GET /grants` |
| `show --principal` | `POST /effective` |
| `verify` | `GET /verify` |
| `check` | `POST /check` |
| `explain` | `POST /explain` |
| `check`/`explain` with `--resource` or `--ctx` | `POST /scope` |
| `grant`, `revoke`, `import` | `POST /transactions` |
| `import --replace` | `POST /replace` |
| `save` | `POST /save` |
| `load` | `POST /load` |

The gateway maps `401` to exit `3` and `403` to exit `4`. Over qIPC, a q error beginning `denied` maps
to exit `4`.

`--principal JSON|@FILE|-` never authenticates a mutation. It is accepted only by `check` and `explain`,
where it is the principal being modelled. This stops a caller inventing an administrator in JSON and
using that object as a credential. A `--principal` that will not parse is exit `1` (it is data, like
`assert --principal`); a `--ctx` value the caller mistyped — heterogeneous, empty, or the wrong JSON
shape — is exit `2` (it is a flag value). A `check`/`explain` answer that is not itself a real boolean
or object (a malformed or hand-rolled gateway response) is refused as exit `1`, never read as an allow.

### Commands

| Command | Effect |
|---|---|
| `show [--group G] [--principal P]` | Return the public grants. With `--principal`, return only what that subject holds. Wildcards render as `*`. |
| `verify [--fail-on error\|warning]` | Lint the live policy. Returns findings and counts; `--fail-on` exits `1` when something at that severity or worse is present. |
| `check ACTION [RESOURCE]` | Pure allow or deny. Also accepts `ACTION:RESOURCE`. A denial exits `4`. |
| `explain ACTION [RESOURCE]` | Return the matched grants or the first rejection reason. A denial exits `4`. |
| `check`/`explain` `--resource R` | Repeat for many resources. Answers with the permitted subset. |
| `check`/`explain` `--ctx JSON` | Declare the axes of the request. Answers with any narrowings of them. |
| `grant G ACTION [RESOURCE]` | Persist one operation atomically. No separate save is needed. |
| `revoke G ACTION [RESOURCE]` | The same, in reverse. Revoking an absent row succeeds and says so. |
| `import FILE [--replace] [--dry-run]` | Apply operations, or explicitly replace from a snapshot. |
| `export FILE [--format json\|csv]` | Atomically write a portable snapshot. |
| `save` / `load` | Operate on the store path configured locally in q. |

> **`kx rbac check` is not `kx auth check`.** This one asks the q engine for a policy decision.
> `kx auth check` does not exist.

### Many resources, and a declared context

Both are **optional**. Without either, the command answers a single-resource question.

```bash
# the permitted subset of several resources
kx rbac check read data.trades --resource data.accounts --resource ref.venues --connect localhost:5010 --json

# declare the axes of the request, and see what comes back narrowed
kx rbac explain read data.trades --connect localhost:5010 --json \
  --ctx '{"from":"2026-01-01T00:00:00","syms":["AAPL","TSLA","MSFT"]}'
```

```json
{ "status": "ok",
  "result": { "allowed": true, "action": "read", "resources": ["data.trades"],
              "obligations": { "from": "2026-05-01T00:00:00.000000000", "syms": ["AAPL", "MSFT"] },
              "declared": ["from", "syms"],
              "reason": "entitled window starts 2026.05.01" } }
```

`declared` echoes the axes you asked about, which is what makes the answer auditable: an obligation is only
legitimate on an axis the caller declared, so the two lists together show the decision was in bounds.

**Either flag routes the question to the seam** (`.kx.auth.explain`) rather than the engine
(`.kx.rbac.explain`), because only the seam sees narrowing. Without them the command asks the engine
directly, so it works against a host running `kx.rbac` on its own. A denial still exits `4`, and carries `denial`.

**The JSON-to-q value mapping is part of the contract**, because JSON has neither a timestamp nor a symbol
and the seam requires an obligation to carry the same q type the caller declared:

| JSON | q |
|---|---|
| a string parsing as ISO-8601 | timestamp |
| any other string | symbol |
| integer / real / boolean | long / float / boolean |
| an array | a vector of whatever its elements map to — and it must be homogeneous |
| `null`, or a nested object | refused: an axis carries a value or a list of them, not a structure |

A wildcard resource (`*`) cannot be combined with either flag — there is nothing named for a policy to narrow.

### Linting a policy

`verify` runs the engine's own lint and returns its findings with a count by severity.

```bash
kx rbac verify --connect localhost:5010 --json
kx rbac verify --connect localhost:5010 --fail-on error     # exits 1 if anything is an error
```

| Severity | Issue |
|---|---|
| `error` | no group can assert an identity |
| `warning` | no group can administer the policy |
| `warning` | an asserter tier also holds non-control-plane grants |
| `note` | a total wildcard grant exists |

**This is not the same question the update paths ask.** A transaction refuses only a change that would
remove the last holder of `assert` on `kx.identity` or `admin` on `kx.rbac`. The lint is advisory and
nothing branches on it, so a policy carrying a total wildcard, or an asserter tier that also holds data
grants, commits like any other. `verify` is how you find out.

`--fail-on` exits `1` and reports `status: "error"`, keeping the findings in `result` so a pipeline can
print them. It is exit `1` rather than `4`: nothing was denied, the policy is simply not in a state you
were willing to accept.

### Import shapes

There are two, under one symmetrical `import` and `export` vocabulary.

```json
{"operations": [
  {"op": "grant",  "group": "trader", "action": "read",  "resource": "data.trades"},
  {"op": "revoke", "group": "trader", "action": "write", "resource": "data.trades"}
]}
```

```json
{"grants": [
  {"group": "policyAdmins", "action": "admin", "resource": "kx.rbac"}
]}
```

An operations file is the ordinary merge form. A `grants` snapshot is rejected unless the caller adds
`--replace`, because replacing a policy is materially different from applying changes, and `--replace`
is likewise rejected for an operations file.

JSON `null` and CSV `*` are wildcards. CSV uses `op,group,action,resource` for operations and
`group,action,resource` for snapshots. Empty, truncated and over-wide rows are rejected.

`--dry-run` sends the candidate to q, which runs structural validation, the lockout guard and the policy
lint, then returns `changed`, `added`, `removed` and `findings` without mutating anything. Use it before
a reviewed batch, or to discover that a proposed replacement would strand the control plane.

## Token cache

`login` writes one JSON credential file, read by `exchange` and by `rbac --server`.

- Path `~/.kx/credentials.json`, overridable with `$KX_AUTH_CACHE`. Directory `0700`, file `0600`.
- Keyed by the `--server` URL, so multiple deployments coexist.
- Each entry holds `access_token`, `refresh_token`, `token_type`, `scope`, `expires_at`, `issued_at`
  and `authorization_server`.
- An expired entry raises auth-required (exit `3`) rather than sending a dead token onward.
- A missing or corrupt cache reads as "no credentials", never as an error.
- `introspect` is stateless and never touches it. Keyring storage is not supported.

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `KX_AUTH_TOKEN` | `introspect`, `exchange`, `assert`, `rbac --server` | The bearer or subject token when not passed as an argument. |
| `KX_AUTH_CLIENT_ID` | `login` | OAuth client id when not registering dynamically. |
| `KX_AUTH_CLIENT_SECRET` | `exchange` | Client secret. Preferred over the flag, which lands in shell history. |
| `KX_AUTH_CACHE` | `login`, `exchange`, `rbac --server` | Override the token-cache path. |
| `KX_AUTH_KDB_USER` | `assert --connect`, `rbac --connect` | qIPC user when `--user` is omitted. |
| `KX_AUTH_KDB_PASSWORD` | `assert --connect`, `rbac --connect` | qIPC password when `--password` is omitted. |
| `KX_MCP_AUTH*` | `introspect` | The verification config a KX MCP server reads. |

## q verbs and their CLI equivalents

The two surfaces do not line up name for name. This is the mapping.

| q verb | CLI |
|---|---|
| `grants[]` | `kx rbac show` |
| `check` | `kx rbac check` |
| `explain` | `kx rbac explain` |
| `.kx.auth.explain` | `kx rbac check`/`explain` with `--resource` or `--ctx` |
| `grant` | `kx rbac grant` |
| `revoke` | `kx rbac revoke` |
| `apply` | no subcommand; `grant`, `revoke` and `import` all commit through it |
| `replace` | `kx rbac import --replace` |
| `save` | `kx rbac save` |
| `load` | `kx rbac load` |
| `setGrants` | none. Use `import --replace`, which persists |
| `effective` | `kx rbac show --principal` |
| `verify` | `kx rbac verify` |
| `report` | `kx rbac verify --fail-on` |
| `configureStore` | none by design. A remote caller never chooses a filesystem path |
| `policy` | none. It is host wiring, not administration |

`setGrants` is the only verb with no route of its own; `import --replace` covers the same use and
persists.

## See also

* [Authorization overview](AUTHORIZATION.md): the model these commands operate on
* [`kx auth` CLI skill](../skills/kx-auth-cli/SKILL.md): agent guidance for the handoffs
* [`kx.rbac` reference](../modules/kx/rbac/docs/references/rbac.md): what the q verbs do underneath
