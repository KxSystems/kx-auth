# `kx.rbac` reference

The peer policy engine behind `kx.auth`'s decision seam. One table, three columns, every grant keyed on
a group.

## Quickstart

```q
q).kx.auth:use`kx.auth
q).kx.rbac:use`kx.rbac
q).kx.rbac.grant[`trader;`read;`data.trades]
1
q).kx.auth.setPolicy .kx.rbac.policy[]
q).kx.rbac.check[`sub`groups!(`alice;enlist`trader);`read;`data.trades]
1b
```

## Exports

| Export | Signature | Description |
|---|---|---|
| `grant` | `grant[group;action;resource]` | Add a grant idempotently. |
| `revoke` | `revoke[group;action;resource]` | Remove the exact grant row. |
| `setGrants` | `setGrants[table]` | Validate and replace the complete grant set. Does not persist. |
| `apply` | `apply[operations;dryRun]` | Apply an ordered `grant`/`revoke` batch as one persisted transition, or return its diff without mutating. |
| `replace` | `replace[table;dryRun]` | Persist and install a complete snapshot as one transition, or dry-run it. |
| `grants` | `grants[]` | Return the current `(grp;act;res)` table. |
| `effective` | `effective[principal]` | Return grants held by the principal's `groups`. Reachable from the CLI as `kx rbac show --principal`. |
| `check` | `check[principal;action;resource]` | Evaluate one decision without connection state. |
| `explain` | `explain[principal;action;resource]` | Return the decision, matching rows, or the first rejection reason. |
| `verify` | `verify[]` | Return policy findings as `(severity;issue;detail)`. Reachable from the CLI as `kx rbac verify`. |
| `report` | `report[fatal]` | Print findings and, when `fatal` is true, signal on errors. |
| `configureStore` | `configureStore[path]` | Configure the snapshot path from local startup code. Remote calls are refused, and so is a path that is a directory. |
| `save` | `save[]` | Persist the grant table to the configured store using temp-then-rename. |
| `load` | `load[]` | Validate and replace the grant set from the configured store. |
| `policy` | `policy[]` | Return the decision function for `kx.auth.setPolicy`. |

Principals passed directly to `effective`, `check` and `explain` must be canonical policy principals
with a top-level symbol `groups` value. `kx.auth` produces that shape for both login and asserted
identities.

**There is no `.kx.rbac.show`.** `show` is a subcommand of the `kx rbac` CLI, fronting `grants[]`.

## Matching

A null action or resource cell is a wildcard. Actions otherwise match exactly: `write` does not imply
`read`. The verb axis has no subsumption because verb sets are small and closed; the ordering concept
would cost more than the handful of rows it saves.

Grant tables contain exactly `grp`, `act` and `res`, all symbol columns. Groups must be non-null;
unexpected columns are rejected rather than ignored.

Resources use dotted paths, and cover runs **segment-wise**, never as a string prefix:

| Grant | Request | Covered |
|---|---|---|
| `data.trades` | `data.trades.price` | yes, a descendant segment |
| `data.trades` | `data.tradesecret` | no, not a segment boundary |
| `data.trades` | `data` | no, cover never runs child to parent |
| null resource | anything | yes, the resource wildcard |
| null action | any action | yes, the action wildcard |

The model has no deny rows and no separate role entity. Resource taxonomy expresses exceptions; IdP
groups are the roles.

Decisions memoise on the `(groups;action)` pair. Every mutation bumps a version counter and the whole
memo is dropped on a version change, because a stale allow is a security bug and grants change rarely.

A decision costs the same regardless of how many grants a subject's groups make applicable — cover is
decided by ancestor membership rather than a per-grant scan. A resource *vector* is also answered in one
vectorised pass rather than one call per resource, since `kx.rbac` installs into `kx.auth.setPolicy` at
rank 4. There is no reason to hand-roll a per-resource loop to keep a batch small.

## Administration

Remote mutations and persistence require the principal in effect to hold `admin` on `kx.rbac`, through a
call to `.kx.auth.authorize`, so a bound asserted principal and an unbound direct-login principal follow
the same policy. Only in-process calls bypass it, meaning `.z.w=0`: the host's own startup
script or console. A qIPC connection from the same machine has a non-zero handle and is gated like any
other client. The bypass is safe because in-process code can call `.kx.auth.setPolicy` and replace the
decision function outright, and it is how the first grant gets made. Remote audit records carry the effective principal and
the connecting login.

`apply` accepts a symbol table with columns `(op;grp;act;res)`, where `op` is `grant` or `revoke`. It
validates every row, builds the complete candidate in order, applies the vital-grant guard to that
**final** candidate, lints it, then writes the snapshot before installing it in memory.

**Only the guard refuses.** `guardVital` signals and the transaction stops. The lint runs on the same
candidate but its findings are reported in the result and nothing branches on them, so a transaction
that lints badly still commits.

**The write is the commit point.** A failed write leaves both the live policy and its memo generation
untouched. `replace` gives the same transaction for an explicitly chosen whole-policy replacement.

With `dryRun=1b` both verbs are public inspection. They return whether the candidate changes anything,
its added and removed rows, and its findings, without needing an admin grant, a configured store, or
changing any state. Operations are ordered and idempotent: revoking an absent grant succeeds with
`changed=0b` and no removed rows.

`setGrants` and `load` replace the whole table. A set without an administration grant locks out remote
administrators until a local call restores one.

### The vital-grant guard

Two grants are guarded, because losing the last holder of either leaves the deployment unrecoverable:

| Grant | Losing it means |
|---|---|
| `assert` on `kx.identity` | no user session could be established |
| `admin` on `kx.rbac` | no remote caller could repair the policy |

The guard is **monotone**: it refuses only a transition that removes the last holder of a grant that
currently has one. Bootstrapping in any order is never blocked, and an already-broken policy can still
be repaired.

### Lint findings

`verify[]` returns, and `report[fatal]` prints. All four are advisory; none blocks a transaction.

| Severity | Issue | Refused by the guard? |
|---|---|---|
| `error` | no group can assert an identity | only if a change removes the last holder |
| `warning` | no group can administer the policy | only if a change removes the last holder |
| `warning` | an asserter tier also holds non-control-plane grants | no |
| `note` | a total wildcard grant exists | no |

The guard and the lint answer different questions. `guardVital` asks whether a change would strand the
deployment, and refuses it. `verify` asks whether the resulting policy is sane, and tells you.

A set can therefore fail `verify` with every update path having run correctly. A host that builds its
policy up from empty and never declares an asserter is never blocked, because the guard only fires on
removal of a holder that exists. A leaky asserter tier and a total wildcard are never refused at all.
A snapshot restored with `load` passes structural validation and the guard without anyone checking it
lints clean.

## Persistence

The host calls `configureStore[path]` locally during bootstrap; remote callers cannot choose a
filesystem path. An administrator then persists live changes with `save[]` and restores the configured
snapshot with `load[]`. `load` replaces rather than merges.

The path names a file. `configureStore` refuses a directory, and so does every write (`save` and a
persisted `apply` or `replace`), in case a directory has appeared at the path since. A refused write
signals before anything is written and leaves the live grants and the policy version unchanged.

The store is the bare `(grp;act;res)` table written with `set` and read with `get`. There is no
intermediate format, so nothing parses it and nothing depends on a config library. Any q process can
query it without loading either module:

```q
q)select from get hsym `$"/etc/kx/grants" where act=`read
grp    act  res
-----------------------
trader read data.trades
```

Transaction metadata is deliberately not stored beside it, and `seg` is re-derived on load rather than
trusted from the file.

Note the ``` hsym `$"…"``` in that example. A store path containing `-` cannot be written as a bare symbol
literal: `` `:/var/kx/rbac-grants `` parses as `` `:/var/kx/rbac `` minus an undefined variable
`grants`. Either keep the path literal-safe or build it with `` `$ ``. See
[q-gotchas](../../../../../docs/q-gotchas.md).

```q
q).kx.rbac.grant[`trader;`read;`data.trades]
1
q).kx.rbac.save[]
`:/etc/kx/grants
```

Keep the reviewable baseline in a version-controlled q script. `grants[]` returns rows in a form
suitable for promoting live changes back into that baseline.

Single-row `grant` and `revoke` stay useful in reviewable startup scripts. Operator tooling should
prefer `apply` and `replace`, which make persistence the default and avoid a live-but-unsaved window.
