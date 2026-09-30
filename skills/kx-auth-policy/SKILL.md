---
name: kx-auth-policy
description: Author and review q host authorization using the kx.auth seam and kx.rbac policy engine. Use when adding grants, protecting q functions, applying aimeta @authorize metadata, choosing between annotation-declared and explicit authorization, initializing loadAnnotations, scoping a request with a declared context and applying the obligations it returns, writing a context-aware policy, or diagnosing a denied action/resource call in a kdb+ host.
---

# Author KX authorization policy

Keep the two identities separate: the connection login authenticates the intermediary; the asserted
principal is the end user. Route every decision through the `kx.auth` Subject/Action/Resource seam and
install `kx.rbac` as the policy implementation.

## Choose the enforcement form

Lead with declared authorization for a stable, published, agent-reachable function:

```q
/ @kind function
/ @name .gw.getTrades
/ @desc Return trades for one instrument.
/ @public
/ @authorize read data.trades
/ @param s {symbol} Instrument symbol.
/ @returns {table} Matching trades.
/ @example .gw.getTrades[`AAPL]
/ @uses trades
.gw.getTrades:.kx.auth.protect {[s]
  select from trades where sym=s};
```

Use an explicit check for private/internal functions, computed actions or resources, request-dependent
targets, and hosts that deliberately do not load aimeta:

```q
deleteTenant:{[tenant]
  resource:`$"tenant.",string tenant;
  .kx.auth.authorize[`delete;resource];
  / mutation follows
  };
```

Keep both forms first-class. Do not invent a static annotation for a dynamic resource.

## Narrow a request instead of refusing it

When a caller may have *part* of what it asked for — some of the resources, a shorter time range, a subset of
instruments — declare the axes and apply what comes back. `authorize` and `entitled` are shortcuts over this:

```q
/ "the narrowing if there is one, else what I asked for" — test MEMBERSHIP, never a null or a fill
narrowed:{[o;k;v] $[k in key o; o k; v]};

getTrades:{[syms;from;to]
  ctx:`syms`from`to!(syms; from; to);                     / what this request WANTS
  o:.kx.auth.scope[`read; `data.trades; ctx];             / signals 'denied, or returns narrowings
  select from trades
    where sym  in    narrowed[o; `syms; syms],
          time within (narrowed[o; `from; from]; narrowed[o; `to; to]) };
```

Rules to hold to:

- **Declare every axis you are willing to have narrowed, and apply every obligation you get back.** A policy
  may only narrow an axis the caller declared, so an axis you omit is one a policy must refuse over rather
  than clip. That is why `authorize` stays boolean: it declares nothing.
- **An absent obligation means "unnarrowed"; an empty one means "nothing".** `` (enlist `syms)!enlist `$() ``
  is an allow that yields no rows — not "no constraint". An applier written `if[count o`syms; …]` returns
  everything and is wrong.
- Pass `::` as the context when there is nothing to declare.
- Use `.kx.auth.explain[principal;action;resources;ctx]` to *inspect* a decision without raising it; it takes
  the principal explicitly, like `.kx.rbac.check`.

To write a context-aware policy, install a rank-4 function through the same `setPolicy`:

```q
/ (principal;action;resources;ctx) -> `allowed`obligations[`reason]
entitlements:{[p;a;rs;ctx]
  ok:.kx.rbac.check[p;a;] each rs;                        / capability first
  if[not any ok; :`allowed`obligations!(0b; (`symbol$())!())];
  o:(`symbol$())!();
  if[not all ok; o:o,(enlist `resources)!enlist rs where ok];
  if[not all rs like "kx.*";                              / every resource but the reserved kx.* control plane
    if[not `from in key ctx;                              / would narrow an undeclared axis: refuse, never allow
      :`allowed`obligations`reason!(0b; (`symbol$())!(); "declare from: the entitled window starts ",string window)];
    if[ctx[`from] < window; o:o,(enlist `from)!enlist window]];
  `allowed`obligations`reason!(1b; o; "entitled window starts ",string window) };
.kx.auth.setPolicy entitlements;
```

The refusal when `from` is missing is the rule, not a nicety. Drop it and a caller who leaves `from` out,
including every `@authorize` function, gets an unnarrowed allow; the seam cannot tell that from "no
constraint".

Four things to get right, each of which the seam or a lockout will otherwise teach you:

1. **Delegate capability, then narrow — do not decide the control plane yourself.** The example above asks
   `.kx.rbac.check` first for a reason: `assert` on `kx.identity`, `admin` on `kx.rbac` and `eval` on `kx.q`
   must still be allowed on an empty context, because `bind`, the HTTP assert gate, the perimeter gate and
   remote administration cannot declare one. A policy that answers those from entitlement data — which has
   nothing to say about them — denies `admin` on `kx.rbac`, and policy repair drops to console access on the q
   process. Delegating defers them instead of exempting them, so there is nothing to remember. If you want the
   boundary explicit, the reserved `kx.*` root makes it one test:
   `` if[`kx ~ first `$"." vs string first rs; :capabilityOnly[p;a;rs]]; ``
2. **Return the declared value's exact q type.** `2026.08.20D09:00:00 > 900000000000` is `1b`, so "clip to 15
   minutes" returned as a duration clips to `2000.01.01D00:15` and passes every row. The seam refuses a
   mismatch rather than obeying it.
3. **Grow the dict with `` o:o,(enlist `k)!enlist v ``** — never `o,:` and never `` o[`k]: ``, which amend a
   value list q has already narrowed to one type and signal `'type` on the second axis.
4. **Keep a large per-user entitlement set in the policy's own state**, versioned and refreshed, never as a
   context axis — validating a narrowing against a 50,000-element axis costs far more than the decision.

## Initialize declared authorization

Define every protected binding before compiling aimeta, then load the hydrated annotation snapshot:

```q
.kx.auth:use`kx.auth;
.kx.rbac:use`kx.rbac;
.kx.aimeta:use`kx.aimeta;

/ grants, policy installation, and protected function definitions

.kx.aimeta.init[];
.kx.auth.loadAnnotations[];
```

`aimeta` is a soft dependency: a host using only explicit checks needs neither `kx.aimeta` nor
`loadAnnotations[]`. A `.kx.auth.protect` wrapper always denies until a successful annotation load.
The loader replaces declarations atomically; an unreadable model, unresolved function, or annotated
binding that is not protected leaves the prior snapshot in force.

## Preserve the security invariants

- Treat `@authorize` as one static `action resource` pair. Aimeta publishes it but does not enforce it.
- `protect` and `@authorize` pass no context: `ctx` is the empty dict `` (`symbol$())!() ``, never `(::)`,
  so test an axis with `` `from in key ctx ``, never `(::)~ctx`. Never protect a function whose data a
  context-aware policy narrows; use `.kx.auth.scope[action;resources;ctx]` and apply the obligations. Under
  a policy that allows when an axis is undeclared, a protected function returns every row.
- Use `.kx.auth.protect {…}`, never an in-body caller lookup or `.z.s` convention.
- Protect q lambdas with 0–7 arguments. The wrapper is a projection (`104h`); code that insists on a
  `100h` lambda or relies on Tier-1 arity introspection must be updated or remain explicit.
- Reserve `kx.*` for module control-plane resources: `kx.identity`, `kx.rbac`, and `kx.q`.
- Keep resources dotted and symbol-literal-safe. IdP group names containing `-` need `` `$"name-with-dash" ``.
- Grant `assert:kx.identity` only to the trusted intermediary tier. An asserter can bind arbitrary groups.
- Keep the reviewable startup baseline as calls to `grant[…]`; use `kx rbac` transactions for live
  administration and promote deliberate changes back into that baseline.

## Administer live policy safely

Use `kx rbac show/check/explain` for public inspection. Use `grant`/`revoke` or an operations import for
ordinary changes; these persist atomically. Reserve `import --replace` for an intentional full snapshot.
Dry-run a reviewed batch, then commit the same idempotent operations:

```bash
kx rbac import policy-ops.json --dry-run --server https://gateway.example --json
kx rbac import policy-ops.json --server https://gateway.example --json
```

An absent revoke is a successful no-op; `changed=false` reports that the row did not exist. Treat
`import --replace` as authoritative for the whole policy. The effective transport principal must hold
`admin:kx.rbac`; `--principal` is accepted only by pure
`check`/`explain` and never authenticates a change. Preserve both vital grants in a replacement:
`assert:kx.identity` and `admin:kx.rbac`.

## Validate the change

From the repo root, run both required gates:

```bash
q tests/test.q
bash demos/local-assertion/run.sh
```

Add a regression for the exact decision rule. For declared functions, cover pre-load denial, the loaded
pair, and a denied caller. Annotation structure is validated atomically by `.kx.auth.loadAnnotations[]`.

Check grant-policy health after initialization with `.kx.rbac.verify[]` in the host, or `kx rbac verify`
over either transport when administering remotely. The lint is advisory: a transaction refuses only a
change that would remove the last holder of `assert:kx.identity` or `admin:kx.rbac`, so a total wildcard
or a leaky asserter tier commits without complaint. `kx rbac verify --fail-on error` exits `1`, which is
what to use in CI.
