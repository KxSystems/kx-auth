# CLAUDE.md

Guidance for coding agents (Claude Code, Codex, …) working on the `kx.auth` module and its companion
CLI: conventions, invariants, q traps and testing.

## What this project is

`kx.auth` is a q module for **identity assertion** on kdb+, plus the **default-deny authorization seam**
a deployment plugs its policy into. `kx.rbac` is the peer policy engine behind that seam, and
`kx-auth-cli` is the client-side `kx auth` CLI that acquires the tokens q refuses to parse.

**Two identities.** The connecting process authenticates the *connection* with a service-account login
(`.z.pw`); the end user is **asserted** on that connection afterwards and never logs in to kdb+. q does
no token parsing and no crypto — it trusts the assertion because of the connection it arrived on, *and*
because the asserting login holds a grant that says it may assert.

**One seam, default-deny.** `authorize[action;resource]` and `entitled[action;resources]` are the
decision verbs; `setPolicy` installs the deployment's decision function. Until then everything is
refused, including "may this caller assert an identity", which is deliberately just another grant.

## Repo structure

```
.
├── modules/kx/auth/
│   ├── init.q          identity, the S/A/R seam and .z wiring
│   └── README.md       auth exports, policy protocol and usage
├── modules/kx/rbac/
│   ├── init.q          the peer RBAC policy engine
│   └── README.md       grants, cover, administration and persistence
├── tests/
│   ├── test.q          driver (runTest/summary), flat module loads, the .t. helpers
│   ├── assertion-gate.q
│   ├── rebind.q
│   ├── login-space.q   the login map, the subject rule, and the two invariants guarding both
│   ├── rbac.q          cover / wildcards / no-verb-subsumption / validation / admin / persistence
│   ├── declared.q      policy-independent @authorize wrappers and atomic aimeta loading
│   ├── perimeter.q     the HTTP asserter backstop and the opt-in qIPC eval gate
│   ├── obligations.q   the context axis: the narrowing rule, the type rule, the unchanged shortcuts
│   └── bench.q         the measured performance exit criterion
├── demos/local-assertion/      qIPC: a trusted intermediary asserts, over two real handles
│   ├── host.q          grants + @authorize declarations, one engine, four questions
│   ├── client.q        the trusted intermediary, over real qIPC
│   └── run.sh          host + client + assertions; also the CI smoke
├── demos/envoy-gateway/        HTTP: a real OAuth proxy asserts — Keycloak + Envoy + KDB-X, in Docker
│   ├── scripts/        run.sh (orchestrator) + checks.sh (curl) + login-check.sh (the CLI)
│   ├── q-scripts/      host.q (granular HTTP routes) + client.q (the raw-qIPC bypass) + helpers
│   ├── envoy/          three listeners: correct, deliberately forgeable, browser oauth2
│   └── keycloak/       the realm export, and notes on what in it is load-bearing
├── packages/kx-auth-cli/   the `kx auth` CLI (Python) — the OAuth-aware client side
│   ├── src/kx_auth_cli/    introspect / login / exchange / assert
│   └── tests/              hermetic pytest suite + its fixtures
├── skills/                 agent guidance for auth policy design and operation
├── docs/
│   ├── adr/            architecture decision records
│   └── q-gotchas.md    q semantics that constrain the implementation
└── README.md · CHANGELOG.md · CONTRIBUTING.md · LICENSE · CLAUDE.md
```

## Module boundaries

- **Each `export` dict is a public contract.** `kx.auth` exports `bind` `current` `valid` `require`
  `authorize` `entitled` `setPolicy` `protect` `loadAnnotations` `configure` `setClaims` `setLoginGroups`
  `setHttpTrustPerimeter` `activate` `activateHttp` `activatePerimeter` `scope` `explain`. `kx.rbac` exports `grant`
  `revoke` `setGrants` `grants` `effective` `check` `explain` `verify` `report` `configureStore` `save`
  `load` `policy` `apply` `replace`.
  Update the corresponding module README with any surface change.
- **`scope` is the one decision path; `authorize` and `entitled` are shortcuts over it.** Do not add a
  second decision route, and do not give `setPolicy` a sibling installer — one slot, one installer, either
  rank. A policy may only narrow an axis the **caller** declared, which is what keeps `authorize` boolean
  whatever policy is installed. `kx.auth` owns no axis vocabulary beyond `resources`.
- **A context-aware policy must allow the control-plane triples on an empty context** — `assert` on
  `kx.identity`, `admin` on `kx.rbac`, `eval` on `kx.q`. `bind`, `httpMayAssert`, `gateEval` and
  `kx.rbac.requireAdmin` cannot declare a context, and three of them are the repair path: a policy that
  refuses them leaves recovery to console access. The two assert gates call the rank-agnostic `allows`
  helper rather than the `policy` slot, because calling a rank-4 policy with three arguments yields a
  **projection** and signals `'type` from inside `bind`.
- **`kx.*` is a reserved resource root** — `kx.identity` (assert), `kx.rbac` (administration), `kx.q`
  (perimeter eval). A host must not use it. Without the reserved root, control-plane targets would share
  the namespace a host's tables occupy, so a host table named `identity` or `rbac` would collide with a
  control-plane resource and a data grant would confer a control-plane capability. q sets the precedent
  by reserving `.z`/`.Q`.
- **`promote` is the single canonicalisation authority.** qIPC's `bind` and HTTP's `fromJson` both route
  through it, which is what makes the two transports yield an identical principal. Do not add a second
  place that shapes a principal; extend `promote`. It is also the **shape contract**: after its coercions,
  a principal whose promoted fields are not the documented q types (`sub` a non-null symbol;
  `groups`/`aud`/`scopes` symbol vectors; `exp` a numeric atom or timestamp; `claims` a dict) is refused by
  name — `bind` signals and the HTTP path answers 400 with `kx.auth: malformed principal: <field> must
  be …` — so nothing downstream defends against junk. `loginPrincipal` is built canonical rather than
  promoted: it is `promote`'s fixed point, pinned by `tests/login-space.q`.
- **`kx.auth` and `kx.rbac` are peer modules.** RBAC supplies the policy function;
  the host installs it with `.kx.auth.setPolicy .kx.rbac.policy[]`. The modules keep independent private
  namespaces. See [ADR 0007](docs/adr/0007-peer-auth-rbac-modules.md).
- **The remaining cross-module dependency is explicit.** Remote RBAC mutation calls
  `.kx.auth.authorize[`admin;`kx.rbac]`; mutation audit reads `.kx.auth.current[]`.
- **Declared authorization belongs to the seam, not the RBAC engine.** `kx.auth.protect` and
  `loadAnnotations` delegate through the installed policy function, so custom policies work unchanged.
  Aimeta is a soft dependency only for hosts opting into annotations; explicit-only hosts never load it.
- **A consumer must assign the module to the global `.kx.auth`** (`.kx.auth:use`kx.auth`), because a
  *remote* caller's `.kx.auth.bind` has to resolve by name. That is a documented requirement on hosts,
  not an internal detail — dotted-name resolution reaching into the returned dict is what makes it work.

## Security invariants

These invariants define the security model and require explicit review when changed.

- **Default-deny everywhere.** `policy` starts as `{[p;a;r] 0b}`. An unset policy and an expired principal
  refuse. An unbound handle decides as its connecting login, whose grants are explicit. There is no
  configurable fail-open.
- **Protected declarations fail closed.** A `protect` wrapper denies until `loadAnnotations[]` has
  atomically associated its token with aimeta's static pair. A failed refresh preserves the prior
  complete snapshot; a successful refresh replaces it. The wrapper always delegates through `authorize`,
  never around the installed policy.
- **`bind` is gated by the same policy it protects.** It consults
  ``policy[loginPrincipal .z.u;`assert;`kx.identity]`` — the *caller's own login principal* as subject,
  before any principal exists. So "who may assert" is one group-keyed grant in the one policy, not a
  second seam, and a different authenticated user on a shared kdb+ cannot forge a `bind`.
- **The fail-closed obligation rule is `closeDecision`, in one place.** `allows` (the assert gates) and
  `authorize` (gateEval, protected functions, `kx.rbac.requireAdmin`) both read it: an allow that still
  carries an obligation none of them can apply is closed to a refusal there and nowhere else. Never
  re-implement the rule at a call site.
- **`assert` dominates every other grant, including administration.** An asserter can bind *any* groups,
  so it is a privilege-escalation primitive, not a peer grant. It belongs to a trusted intermediary
  serving many principals, never to a tool representing one.
- **The subject rule: bound principal, else the caller's own login.** `current[]` falls back to
  `loginPrincipal .z.u` rather than failing. Safe because a login is never elevated: an unmapped login
  has empty groups and matches no grant, so the gate is "no grant covers you", not "nothing is bound".
  **Operator hazard:** an unbound handle
  therefore decides as the connecting login, so keep a trusted asserter's tier to control-plane grants
  only. Grant that tier data as well and an unbound handle reaches the data.
- **Login and asserted principals use one decision path.** A login-derived principal has exactly the
  shape `promote` produces — it is built canonical, and `promote` on it is the identity, pinned by
  `loginPrincipalIsAFixedPointOfPromote` — and nothing downstream (`valid`/`require`/`authorize`/
  `entitled`/the engine) may branch on how it arrived; provenance is readable for audit via `iss`
  (`` `kdb.local ``) only. Pinned by `tests/login-space.q`, so a future `$[` on provenance inside a
  decision path fails a test. An anonymous login (null `.z.u`) decides as a groupless nobody rather than
  being refused as malformed.
- **Administration follows the subject rule.** Remote mutations call
  `` .kx.auth.authorize[`admin;`kx.rbac] ``. A bound asserted principal and an unbound direct-login
  principal are equally valid administrators when their groups hold the grant. Only `bind` authorizes
  the connecting login explicitly, because it runs before an asserted principal exists.
- **A re-bind replaces the principal wholesale.** No field of the previous principal survives. This is
  what stops a stale `tenant` outliving a token refresh on a cached connection, and it is pinned by
  `tests/rebind.q` — including the structural invariant `0h = type value bound`.
- **`check` is pure and takes an explicit principal.** Unlike `entitled`, which
  reads the *bound* principal via `require[]`, `check` takes its subject as an argument. That asymmetry
  looks like an inconsistency and is the feature: it is why a q process with this module loaded already
  *is* a policy service a non-q caller can consult over qIPC. Do not "simplify" it into alignment.
- **The administration gate is remote-only.** A local `.z.w=0` call bypasses it because that caller can
  already redefine the module. This is the bootstrap path for the first grant.
- **Resource cover is segment-wise, never string prefix.** `` `data.trades `` must not cover
  `` `data.tradesecret ``, nor `` `data `` cover `` `datastore.x ``. A naive `like` returns `1b` for both.
  Pinned by `tests/rbac.q`; it is the single most important behaviour in the engine.
- **The memo must never outlive a mutation.** Every mutation verb bumps a version counter and the whole
  memo is dropped on a version change. A stale *allow* is a security bug, so invalidation is wholesale
  rather than per key — grants change rarely, so there is nothing to buy by being clever here.
- **Policies read *promoted* fields, never raw `claims`.** `claims` stays char vectors: an audit and
  escape-hatch payload, deliberately not symbolised so high-cardinality values like `jti` never intern.
  When present it must be a dictionary; `promote` refuses anything else.
- **`activate` / `activateHttp` are opt-in.** A bare `use` must never change process behaviour, so
  handler wiring is a separate explicit call — and it **composes** with any prior `.z` handler rather than
  clobbering it. Activation verbs are idempotent; a repeated call must not capture the module's own
  wrapper as its prior handler. Any future activation verb follows the same rules.

## The `kx auth` CLI (`packages/kx-auth-cli`)

The Python half. It exists because the q module deliberately has **no OAuth or JWT awareness** — so
token acquisition, exchange and claims projection happen client-side, and `kx auth assert --connect`
binds the result over qIPC. It is also the module's shell-level exerciser: a kdb+ running `kx.auth`
can be driven end-to-end with no MCP server in the path.

- **The fastmcp-free invariant.** The CLI depends on `kx-auth-core` + `httpx` only and must never
  import `fastmcp`. Pinned by `test_assert_cmd_import_is_fastmcp_free`. PyKX is imported lazily and
  ships in the optional `[qipc]` extra, so the base install stays light.
- **`kx-auth-core` is not in this repo.** It is a separate package; the CLI consumes it as a published
  wheel and touches only three of its functions (`verify_token`, `exchange`, and the claims
  projection). Do not vendor or fork it here, and do not reimplement anything it owns.
- **q owns promotion.** The projected principal is a *ferry payload*, not a decided identity: groups
  and tenant are derived by `.kx.auth.promote`, never in Python. So `assert` without `--connect` is an
  indicative preview. Never add promotion logic to the CLI — that is the second-implementation
  mistake the design exists to avoid.
- **The exit-code contract is a public contract**: `0` ok · `1` error · `2` usage · `3` auth-required ·
  `4` denied. Every command supports `--json`. Changing either is a contract change.
- **One boundary, `kx_auth_cli/envelope.py`.** Every command returns its result or raises a `CliError`
  subclass (`UsageError`, `AuthRequired`, `Denied`, or the base for an operational error) and runs behind
  `guarded`, which owns the envelope, the exit code and the "never a traceback" rule. No command declares
  exit constants, prints an envelope or catches its own exceptions for exit-code purposes; `--json` is
  declared once. A principal q refuses fails `bind` with the stable prefix `kx.auth: malformed principal`,
  which `assert` reports verbatim as exit 1, distinct from an assert-gate `denied:` (exit 4) and from a
  target that lacks the module.
- **Version is derived from git tags** (`hatch-vcs`, `pyproject.toml`) on the CLI's own `cli-vX.Y.Z`
  tags. The number matches the modules' `vX.Y.Z` release and `kx-auth-core`'s: the family shares a
  version, and `kx-auth-core` is pinned to the same minor.

## Conventions for q code

- One file, one flat private namespace inside the module; module-global state is mutated with `::`.
- In-module sibling loads use `\l ::file.q` (module-relative), not a bare path.
- No observable side effects at module load. `use` yields a dict; nothing else happens.
- Blank comment lines carry a trailing `.` — see the first trap below.
- Runtime comments state contracts, security invariants, operational risks, or non-obvious constraints.
  Detailed q behavior belongs in [`docs/q-gotchas.md`](docs/q-gotchas.md); architectural rationale belongs
  in [`docs/adr/`](docs/adr/).

## q implementation notes

Read [`docs/q-gotchas.md`](docs/q-gotchas.md) before changing dictionary storage, promotion, memoization,
module-private qSQL, handler parameter names, or persistence function names. Keep detailed explanations
there rather than duplicating them in runtime source.

## Testing

```bash
q tests/test.q                        # from the repo root — exits 0 on green, 1 on any failure
bash demos/local-assertion/run.sh     # the demo, with assertions; the only `use`-path proof
```

Both, always, for any q change.

A third suite, `bash demos/envoy-gateway/scripts/run.sh`, drives the **HTTP** path against a real Envoy and
Keycloak in Docker. It is not part of the default gate — it needs a Docker daemon and image pulls — but it
is the only thing that exercises `serveHttp`, `httpMayAssert`, `setHttpTrustPerimeter` and
`activatePerimeter` against a real proxy and a real socket, so **run it for any change to the HTTP or
perimeter half of `init.q`**. `tests/perimeter.q` covers those verbs over synthetic header dicts and says
so at its own head; it exercises the duplicate-header guard only over a synthetic dict, and cannot see how a real socket presents duplicate headers, a real second login, or handler composition. They cover different things: the suite loads both modules **flat**
(`\l`) so it can assert on private state, and therefore never exercises the module path or a real
socket; the demo loads them through `` use`kx.auth `` and `` use`kx.rbac `` over two real connections
and a real second login. See [tests/README.md](tests/README.md) for the three conventions the suite
depends on — the `.t.` prefix rule, the fact that a check must **signal** rather than return a
boolean, and the `KNOWN FAILING` marker on a check that pins an unfixed bug.

A check pinning an unfixed bug asserts the behaviour we *want*, never today's buggy output, so the fix
makes it pass. Those checks fail until then; the marker says which bug.

For a CLI change, from `packages/kx-auth-cli/`:

```bash
uv pip install -e '.[qipc]' --group dev   # once
pytest                                     # hermetic: no live IdP, no kdb+
```

The CLI suite is deliberately hermetic — an in-process mock authorization server for `login`, an
injected fake `pykx` for `assert --connect`. That means **no test there proves the CLI works against a
real q process**, which is what `demos/local-assertion/cli-check.sh` is for: it drives the live demo
host with the real CLI and auto-skips unless the CLI and PyKX are installed. Install the `[qipc]` extra
and `run.sh` picks it up. Touching `assert` means running both.

Add a test for every new decision rule, in the layer that can actually see it: anything about handles,
logins or connection lifecycle belongs in the demo client, not the in-process suite.

## Before committing

1. `q tests/test.q` and `bash demos/local-assertion/run.sh` — both green. Touched the CLI? `pytest`
   from `packages/kx-auth-cli/` too.
2. Add or update a test for the behaviour you changed.
3. Changed an `export` dict, the principal shape, or the assert convention? Update the corresponding
   [`kx.auth`](modules/kx/auth/README.md) or [`kx.rbac`](modules/kx/rbac/README.md) README, and note it as
   a contract change in the commit message. Same for the CLI's command surface, `--json` envelope or
   exit codes — those are contracts too, documented in
   [its README](packages/kx-auth-cli/README.md).
4. User-visible change? Add a bullet to `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
5. Structural or ways-of-working change? Update this file.
