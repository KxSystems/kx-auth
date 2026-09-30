# Demo — identity assertion and four RBAC sets over one engine

The whole module, end to end, against a real kdb+ process over real qIPC. One command:

```bash
bash demos/local-assertion/run.sh
```

Prerequisites: a licensed `q` (KDB-X), `kx.auth`, `kx.rbac`, and aimeta on the module path. Nothing else
— no Docker, IdP, or Python.

Add `--keep` to leave the host running so you can connect and poke at it by hand, `--port N` to move
it off `:5011`.

## What it shows

[`host.q`](host.q) is a plain kdb+ process with two seeded tables. It loads `kx.auth`, logs a service
account in through a standard `-U` user file, declares its grants through **`kx.rbac`'s own admin
verbs**, and installs the engine — and that single engine answers four different questions:

| Set | Question | Grants |
|---|---|---|
| **assert gate** | may this *connection* assert an identity at all? | `superUsers` may `assert` on `kx.identity` |
| **capability** | may this *principal* use the tool? | `viewer`+`trader` may `query` on `kdbx.sql` |
| **data gate** | may this principal touch this *data*? | `trader` may `read` `data.trades`+`data.instruments`, `write` `data.trades` |
| **analytic** | may this principal run a published calculation? | `trader` may `exec` `analytic` |

"Data vs capability vs assert" is only *which resource a row names*. There is no second subject column,
no per-set branch, no host-written decision function, and the engine never looks at where the subject
came from.

The `grant[…]` calls in `host.q` **are** the baseline: deployment-as-code, reviewable in git. A
kdb-format `save` snapshot is not diffable, which is why the q script stays the artifact under review and
`grants[]` prints copy-pasteably when a live change should be promoted into it.

[`client.q`](client.q) is the trusted intermediary — the stand-in for an application server or gateway.
It authenticates as the service
account, binds a principal for alice or bob, and calls the host's gated verbs on their behalf. It
asserts more than twenty properties and exits non-zero on any failure, which is why `run.sh` doubles as a CI
smoke test.

[`cli-check.sh`](cli-check.sh) drives the *same* host with the
[`kx auth` CLI](../../packages/kx-auth-cli/) instead of q, and is the only place the CLI meets a real
kdb+ process — its own pytest suite injects a fake `pykx`, so nothing there proves the wire types, the
promotion readback or the assert gate actually work over a socket. It runs after `client.q` and
**auto-skips** unless the CLI and PyKX are installed, so the demo keeps its zero-prerequisite promise:

```bash
uv pip install -e 'packages/kx-auth-cli[qipc]'   # then run.sh picks the CLI leg up automatically
```

It also drives `kx rbac` as the direct-login administrator and pins the idempotent absent-revoke
acknowledgement over real qIPC. Other things only a live run can pin: that `groups` comes back
**promoted by q** (the CLI cannot derive it — `.kx.auth.promote` is the single promotion authority),
and that its negative cases are real q refusals rather than a crashed interpreter, since both return
exit 1. The live checks parse the complete `--json` stdout strictly, pinning the CLI's one-envelope
contract even when PyKX Community is installed.

Three logins in the `-U` file make the privilege model visible, and all three clear the password gate —
the point being that clearing it buys nothing on its own:

| Login | In the login map as | Holds |
|---|---|---|
| `kxmcp` | `superUsers` | `assert` on `kx.identity` — it may act for others |
| `padmin` | `policyAdmins` | `admin` on `kx.rbac` — it may change the policy, and may **not** assert |
| `intruder` | *(unmapped)* | nothing |

The headline is the third and fourth lines below: **alice and bob both clear the capability check, and
only alice clears the data gate.** Two independent grant sets, one engine, and a denial that names
which gate refused.

```
  ok    unboundHandleDenied                     authenticated ≠ authorized: unbound falls back to the
                                                caller's own login, which holds no data grant
  ok    aliceBindsAndReads                      the terminus asserts alice; her grants take effect
  ok    aliceWriteAllowed                       read and write are separate rows — she holds both
  ok    aliceDeleteDenied                       ... and no verb implies another, so delete is refused
  ok    aliceClearsCapabilityAndData            capability + data, both satisfied
  ok    aliceRunsDeclaredAnalytic               @authorize exec analytic is enforced by protect
  ok    bobBindsOnSecondHandle
  ok    bobPassesCapabilityFailsDataGate        THE HEADLINE: refused by "read on data.trades", not by
                                                "query on kdbx.sql" — the capability check passed
  ok    grouplessPrincipalDeniedAtCapability    ... and no groups at all is refused one gate EARLIER
  ok    twoHandlesStayIndependent               two sockets, two principals, no interference
  ok    rebindReplacesWholesaleOverIpc          a refreshed token drops the previous claims
  ok    entitledScopesDownPerPrincipal          entitled[] returns the readable subset in one hop
  ok    authenticatedIntruderCannotAssert       a real second login, refused at bind — "who may assert"
                                                is a grant on the login's groups, not trust in the socket
  ok    remoteMutationDeniedWithoutAdminGrant   alice has no administration grant
  ok    remoteMutationAllowedWithAdminGrant     padmin administers as a direct principal
  ok    remoteStoreConfigurationDenied          even an admin cannot choose the host's filesystem path
  ok    remoteMutationPersistsWithSaveLoad      grant -> save -> revoke -> load restores the grant
  ok    policyAdminMayNotAssert                 administration does not imply identity assertion
  ok    assertedAdminMayMutatePolicy            asserted and direct principals use the same policy
  ok    explainNamesTheMissingGrantOverIpc      a denial an agent can act on, not just "denied"
  ok    readSideVerbsNeedNoAdminGrant           grants[] / effective[] are readable without admin
  ok    setGrantsValidatesAndPreservesOverIpc   a malformed set fails and the live one is untouched
  ok    aGrantTakesEffectLiveWithNoReload       THE PAYOFF: grant -> allowed -> revoke -> denied,
                                                with no restart and no edited file
```

## Why this demo exists beyond being a demo

Many of those checks cover properties the in-process test suite **cannot** reach, because in-process
`.z.w` is `0i` and `.z.u` is fixed: two-handle independence, the wholesale re-bind over a live socket, a
genuinely different authenticated login refused at `bind`, and — since the administration gate
deliberately exempts local callers — the entire *remote* half of `admin:kx.rbac`.

This is also the module-path test: it loads both peers as a host does, through `` use`kx.auth `` and
`` use`kx.rbac ``, while the unit suite loads them flat. `explain`, `effective`, and `setGrants` exercise
query-bearing exports in their deployed namespaces.

So run `run.sh` beside `q tests/test.q`, not instead of it.

## Things worth trying by hand

Start it with `--keep`, then connect as the service account and break something:

```q
h:hopen `$":localhost:5011:kxmcp:s3cret-svc-pw"
h ".demo.getTrades[`AAPL]"                          / 'denied — nothing bound yet
h (`.kx.auth.bind; `sub`groups!(`you; enlist `viewer))
h ".demo.listTables[]"                              / empty — `viewer reads nothing
h (`.kx.auth.bind; `sub`groups!(`you; enlist `trader))
h ".demo.listTables[]"                              / both tables
h ".kx.rbac.grants[]"                               / the whole policy, as one table
```

Ask *why*, not just whether — this is the verb worth knowing about:

```q
h (`.kx.rbac.explain; `sub`groups!(`you; enlist `viewer); `read; `data.trades)
/ reason: "group(s) viewer hold no read grant (they hold: query:kdbx.sql)"
```

Change the policy live, as an administrator, and watch a decision change with no restart:

```q
a:hopen `$":localhost:5011:padmin:s3cret-padmin-pw"
a (`.kx.rbac.grant; `viewer; `read; `data)     / a PARENT grant — cover does the rest
h ".demo.listTables[]"                              / now both tables, for a plain `viewer
a (`.kx.rbac.revoke; `viewer; `read; `data)
```

And confirm cover is segment-wise rather than string prefix:

```q
a (`.kx.rbac.grant; `viewer; `read; `data.trades)
h (`.kx.rbac.check; `sub`groups!(`you;enlist `viewer); `read; `data.trades.price)  / 1b
h (`.kx.rbac.check; `sub`groups!(`you;enlist `viewer); `read; `data.tradesecret)   / 0b
```

The `grant[…]` calls in [`host.q`](host.q) remain the reviewable baseline: drop `trader`'s write row
there and re-run, and `aliceWriteAllowed` fails with
`denied: alice not permitted write on data.trades`.

## What this demo is not

It stops at the kdb+ boundary. The client hand-writes the principal that a trusted gateway would derive
from a verified token; token validation is intentionally outside this module.

It also does not show every part of the engine. The grants here are all leaf resources, so **cover** is
only visible if you add a parent grant by hand (above); `save`/`load` are exercised by the test suite
rather than here, since the demo's whole point is that the q script is the baseline. Declared
authorization is exercised directly: `.demo.getTrades` publishes `read data.trades` and
`.demo.tradeSummary` publishes `exec analytic`, both enforced structurally with `.kx.auth.protect`.
Write/delete and tool-capability checks remain explicit, showing where dynamic or internal checks stay
first-class.
