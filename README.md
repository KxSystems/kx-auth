# Identity and authorization for KDB-X

`kx.auth` and `kx.rbac` are peer q modules, and `kx auth` is the CLI that does the OAuth work q
deliberately will not. Together they let a kdb+ process act on behalf of an end user whose identity was
authenticated **upstream**, by a trusted gateway, proxy or application, without that user logging in to
kdb+ directly. `kx.auth` carries the identity and provides a default-deny authorization seam; `kx.rbac`
is the policy engine that fills it.

> **New here, or wondering why any of this is shaped the way it is?**
> [**Authorization for kdb+**](docs/AUTHORIZATION.md) is the place to start. It covers the problem these
> modules solve, the policy contract, where authorization is enforced and where it deliberately is not,
> and the supported deployment topologies.

## Why

- **Two identities, cleanly separated.** The connecting process authenticates the *connection* with a
  service-account login; the end user is **asserted** on that connection afterwards and never logs in.
  `.z.pw` only ever sees the service account.
- **A default-deny Subject / Action / Resource seam.** `authorize[action;resource]` and
  `entitled[action;resources]` are the decision verbs. Until a deployment installs a policy, every
  question answers *no*, including "may this caller assert an identity at all".
- **An RBAC engine behind that seam, so you don't write the policy function.** `kx.rbac` is one table of
  `(group; action; resource)` grants with segment-wise cover, wildcards, no verb subsumption and no deny
  rules, plus verbs to declare, inspect, verify, explain and persist it. A single decision costs ~3 µs.
  The policy persists as native kdb data, so there is no config format to parse and any q process can
  read the grant table and query it directly.
- **One promotion path for both transports.** qIPC and HTTP converge on a single canonicaliser, so a
  policy reads the same principal shape regardless of how the identity arrived — and it refuses a
  principal it cannot canonicalise, so a policy never sees junk.
- **No mandatory runtime dependencies.** Pure q, no shared objects, no network calls. Metadata-declared
  enforcement adds a soft aimeta dependency for hosts that opt into it.
- **An OAuth-aware client for the part q refuses to do.** The [`kx auth` CLI](packages/kx-auth-cli/)
  handles token acquisition, RFC 8693 exchange and the claims projection, and administers policy over
  either transport. See [choosing a path](docs/KX_AUTH_CLI.md#choosing-a-path).

## Quickstart

```q
/ host.q
.kx.auth:use`kx.auth;                                 / assign to the global so a REMOTE .kx.auth.bind resolves
.kx.rbac:use`kx.rbac;
.kx.auth.activate[];                                  / wire .z.pw / .z.po / .z.pc, composing with any priors

.kx.auth.setLoginGroups[(enlist `svcuser)!enlist `superUsers];   / what groups that LOGIN carries

.kx.rbac.grant[`superUsers; `assert; `kx.identity];         / who may assert an identity
.kx.rbac.grant[`trader;     `read;   `data.trades];         / and who may read what
.kx.auth.setPolicy .kx.rbac.policy[];             / install the peer engine explicitly

getTrades:{[s]
  .kx.auth.authorize[`read;`data.trades];             / 'denied unless the bound principal may read trades
  select from trades where sym=s };
```

The trusted caller then connects as the service account and asserts a user:

```q
h:hopen `$":localhost:5011:svcuser:pw";
h(`.kx.auth.bind; `sub`groups!(`alice; enlist `trader));   / refused unless the CALLER may assert
h(`getTrades;`AAPL);
```

Run the whole thing, with checks, in one command:

```bash
bash demos/local-assertion/run.sh
```

With a real identity in the picture, the `kx auth` CLI replaces the hand-built principal above — it
performs the same `bind` handshake, and reports back what q *promoted* the principal to:

```bash
# a platform-issued workload token, exchanged and asserted — no browser, no server in between
export KX_AUTH_TOKEN="$(kubectl create token ingest-sa \
  | kx auth exchange --audience kdbx --token-url https://idp/token --json | jq -r .result.access_token)"

kx auth assert --connect localhost:5011 --user svcuser \
  --probe ".kx.auth.authorize[\`read;\`data.trades]" --json
```

## Documentation

- [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md) — the overall approach: the problem, the policy
  contract, the enforcement boundary, topologies and vocabulary. Start here.
- [modules/kx/auth/README.md](modules/kx/auth/README.md) — identity assertion, policy seam and transports
- [modules/kx/rbac/README.md](modules/kx/rbac/README.md) — grants, cover, administration and persistence
- [packages/kx-auth-cli/README.md](packages/kx-auth-cli/README.md) — the `kx` CLI: token acquisition,
  exchange and assertion plus atomic `kx rbac` policy administration
- [demos/local-assertion/](demos/local-assertion/) — the runnable walkthrough: identity assertion plus
  four RBAC sets enforced by one engine, and a grant taking effect live with no reload
- [demos/envoy-gateway/](demos/envoy-gateway/) — the same engine reached over **HTTP through a real OAuth
  proxy**: Keycloak + Envoy + KDB-X in Docker. The topology for interactive human access with no MCP server
  in the path, and where an appended `x-kx-principal` header is shown failing closed against a
  deliberately misconfigured listener
- [tests/README.md](tests/README.md) — how to run the suite, and the conventions it depends on
- [skills/kx-auth-policy/](skills/kx-auth-policy/) — agent guidance for authoring grants and choosing
  declared versus explicit enforcement
- [skills/kx-auth-cli/](skills/kx-auth-cli/) — agent guidance for authentication handoffs, promoted
  principals, policy inspection and safe atomic changes
- [docs/decisions.md](docs/decisions.md) / [docs/q-gotchas.md](docs/q-gotchas.md) — architecture
  decisions and q implementation constraints for maintainers
- [CONTRIBUTING.md](CONTRIBUTING.md) / [CLAUDE.md](CLAUDE.md) — working on the module itself

## Install

Each module carries its own install guide, and both follow the same shape — put the module on the
KDB-X module path (`$QPATH`, default `$HOME/.kx/mod`), then bootstrap it:

* [`kx.auth` install guide](modules/kx/auth/docs/install.md)
* [`kx.rbac` install guide](modules/kx/rbac/docs/install.md)

The two are peers and are normally installed together: `kx.rbac` supplies the decision function that
`kx.auth`'s seam is otherwise missing.

The CLI is a separate, optional Python install — nothing in the q modules depends on it:

```bash
uv tool install 'kx-auth-cli[qipc]'     # or: pipx install 'kx-auth-cli[qipc]'
```

See [its README](packages/kx-auth-cli/README.md#install) for the extras and running it with `uvx`.

## Status

Pre-1.0. Everything described here is built and tested. None of it is frozen yet.

A handful of surfaces are treated as public contracts: the two modules' exports, the principal shape a
policy reads, the `(grp;act;res)` grant schema, the store file format, and the CLI's commands, JSON
envelope and exit codes. Before 1.0 those can still change.

Built and covered by tests: identity assertion over qIPC and behind an HTTP gateway, the default-deny
seam, the `kx.rbac` engine with atomic transactions and persistence, declared authorization through
aimeta annotations, the opt-in perimeter gate, the `kx rbac` CLI over both transports, and a runnable
Keycloak plus Envoy topology.

What a 1.0 still needs:

- **A distribution path.** Both modules install by copying or symlinking onto the module path. There is
  no package manager story yet.

## Related

- [KxSystems/aimeta](https://github.com/KxSystems/aimeta) — the metadata model whose `@authorize`
  annotation publishes the permission a function needs
