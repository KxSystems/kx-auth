# `kx.auth` reference

Identity assertion and the default-deny Subject/Action/Resource seam.

## Quickstart

```q
q).kx.auth:use`kx.auth
q).kx.auth.setPolicy[{[p;a;r](a=`assert)and r=`kx.identity}]
q).kx.auth.bind[`sub`groups!(`alice;enlist`trader)]
q).kx.auth.current[]`sub
`alice
```

## Exports

| Export | Signature | Description |
|---|---|---|
| `bind` | `bind[principal]` | After policy permits the caller's login to `assert` on `kx.identity`, promote and bind the principal dict to the current handle (`.z.w`). A refused bind signals and leaves the handle as it was; see [A refused bind changes nothing](#a-refused-bind-changes-nothing). |
| `current` | `current[]` | The principal in effect: the request principal, else the one bound to this handle, else the caller's own login. |
| `valid` | `valid[]` | `1b` if the principal in effect is unexpired. An absent `exp` never expires. |
| `require` | `require[]` | Default-deny: signals `'denied` when no valid principal is in effect, else returns it. |
| `authorize` | `authorize[action;resource]` | Require a valid principal and enforce the installed policy; signals `'denied` on refusal, else returns the principal. One resource, no declared context — so it refuses (rather than silently applies) any narrowing the policy hands back. |
| `entitled` | `entitled[action;resources]` | Return the subset of resources the valid principal may reach. Answers with an empty vector of the same type rather than signalling. |
| `setPolicy` | `setPolicy[fn]` | Install the decision function, at **either** rank: `(principal;action;resource) -> boolean`, or `(principal;action;resources;ctx) -> obligations`. The default denies everything. |
| `protect` | `protect[lambda]` | Return an arity-preserving wrapper enforcing the lambda's loaded `@authorize` declaration. It declares no context, so use it only where the policy decides by capability alone. |
| `loadAnnotations` | `loadAnnotations[]` | Locally load aimeta's static declarations as one atomic snapshot. |
| `configure` | `configure[(`user;"pw")]` | Set the service account `.z.pw` accepts. This replaces the prior `.z.pw` rather than composing with it: once set, only this account logs in, and any login the prior verifier would have accepted is refused. Leave it unset to keep the prior verifier. |
| `setClaims` | `setClaims[paths]` | Configure the dotted claim paths used to promote `groups` and `tenant`. Paths are strings; a symbol is coerced, anything else refused. See [Claim paths](#claim-paths). |
| `setLoginGroups` | `setLoginGroups[map]` | Declare what groups a kdb+ **login** carries. Partial updates merge; unmapped logins stay default-deny. |
| `setHttpTrustPerimeter` | `setHttpTrustPerimeter[b]` | Opt into trusting the HTTP principal header on network perimeter alone. Defaults `0b`; every use emits an audit warning. |
| `activate` | `activate[]` | Idempotently install `.z.pw`, `.z.po` and `.z.pc`. |
| `activateHttp` | `activateHttp[]` | Idempotently install composed `.z.ph`/`.z.pp` for per-request assertion behind a trusted gateway. |
| `activatePerimeter` | `activatePerimeter[]` | Idempotently install the opt-in coarse `.z.pg`/`.z.ps` gate, requiring `eval` on `kx.q`. |
| `scope` | `scope[action;resources;ctx]` | The general decision verb: many resources, an optional declared context, and **obligations** out. Signals `'denied` on refusal. |
| `explain` | `explain[principal;action;resources;ctx]` | The same decision for an explicitly-passed principal, reported rather than raised: `` `allowed`obligations`reason`denial ``. |

`promote`, `serveHttp`, `httpMayAssert` and `clear` are **not exported** and cannot be reached through
`use`. They are described below as behaviour, not API.

## The principal

A dict describing the subject. The module inspects `exp` for validity, promotes configured claims into
policy-facing fields, and checks permissions through the installed policy.

Promotion is the single canonicalisation authority: both qIPC's `bind` and the HTTP path route through
it, which is what makes the two transports yield an identical principal. It adds `groups`, symbolises
`sub`, `client` and `iss`, widens `aud` and `scopes` to symbol vectors, resolves `tenant`, and
canonicalises a unix-seconds `exp` to a q timestamp so it compares directly to `.z.p`. It coerces what it
can and **refuses** what it cannot: a principal whose fields do not have the shapes below fails `bind`
with `kx.auth: malformed principal: <field> must be <what>, got <type>`, and the HTTP path answers `400`
with the same text. One field is named per refusal, and never its value.

| Field | After promotion | Notes |
|---|---|---|
| `sub` | non-null symbol atom | derived from `claims.sub`, else `client`, when absent; a principal with no identity does not bind |
| `client`, `iss`, `tenant` | symbol atom, null allowed | when present |
| `groups` | symbol vector, empty allowed | always present; taken from the configured claim path when not given |
| `aud`, `scopes` | symbol vector, empty allowed | when present |
| `exp` | numeric atom of unix seconds, or a q timestamp | canonicalised to a timestamp; a too-narrow short is left as-is and denies |
| `claims` | dictionary | when present; never symbolised |
| anything else | untouched | `act` and unknown keys pass through |

**Policies read promoted fields, never raw `claims`.** `claims` stays char vectors. It is an audit and
escape-hatch payload, deliberately not symbolised so high-cardinality values like `jti` never intern.

When the caller binds via PyKX, string claim values arrive as q **symbols**, so compare them as symbols
rather than applying `` `$ ``.

### Claim paths

`setClaims` takes a dict from promoted field to a dotted path into `claims`, and merges it over the
defaults `` `groups`tenant!("";"tenant") ``. An empty `groups` path means "search `groups`, then
`realm_access.roles`, then `roles`".

```q
.kx.auth.setClaims `groups`tenant!("realm_access.roles";"org.tenant")
```

A path is a **string**. A symbol such as `` `realm_access.roles `` is accepted and stored as its string.
Any other value is refused by name, `kx.auth.setClaims: the path for <field> must be a string or a
symbol, got type <n>`, and a refused call changes no path.

## The subject rule

A connection's subject is the request principal if one is set, else the principal bound to the handle,
else the caller's own login.

### A refused bind changes nothing

`bind` checks the assert gate and promotes the principal before it touches the handle. If either
refuses, `bind` signals and the handle keeps whatever it had: the previously bound principal, or none,
in which case requests decide as the connecting login. A refused re-bind does **not** clear the earlier
principal.

A caller that re-binds a handle for a new user must therefore treat a bind error as fatal for that
request. If it catches the error and sends the request anyway, the request runs as the previous user.
The safe pattern is one handle per principal, or closing the handle when a bind fails.

A kdb+ login carries no IdP groups, so `setLoginGroups` declares what groups a login holds. It is the
local-identity sibling of `setClaims`. A login-derived principal is built in exactly the shape promotion
produces — `promote` on it is the identity, pinned by `loginPrincipalIsAFixedPointOfPromote` — and carries
`` iss:`kdb.local `` so provenance stays readable for audit. Nothing downstream branches on how the
principal arrived. An anonymous login (a client that sent no credentials has a null `.z.u`) decides as a
groupless nobody rather than being refused as malformed.

The fallback is never elevated: it is only ever the caller's own login, and an unmapped login resolves
to empty groups, which matches no grant. A vanilla kdb+ with `-U` and no login map is default-deny.

> **Operator hazard.** Because an unbound handle decides as the connecting login, keep a trusted
> asserter's tier to control-plane grants. Grant it `assert` and nothing else and the fallback is inert;
> grant that same tier data access and an unbound handle reaches the data.

## Reserved resource root

Resource paths are dotted, and `kx.*` is reserved for the module's own control plane.

| Resource | Purpose |
|---|---|
| `kx.identity` | the assert target: may this caller assert an identity? |
| `kx.rbac` | the policy-administration target |
| `kx.q` | raw q evaluation at the perimeter |

A host must not put its own resources under that root. Control-plane targets would otherwise sit in the
namespace a host's tables occupy, so a host table named `identity` or `rbac` would collide with a
control-plane resource and a data grant would confer a control-plane capability. q sets the precedent by
reserving `.z` and `.Q`.

The reservation is convention and documentation, not enforcement: the engine treats `kx.*` as an
ordinary dotted path.

Bare q symbol literals admit letters, digits, `.` and `_`, but not `-`. Resources and verbs are yours to
name and stay literal-safe by construction; group names are your IdP's and may need `` `$"emea-desk-3" ``
in a host script. See [q-gotchas](../../../../../docs/q-gotchas.md) for the full trap.

## Usage

`require[]` when a function needs a valid identity but has no distinct action or resource:

```q
principalSummary:{[]
  p:.kx.auth.require[];            / 'denied when unbound or expired
  `sub`groups#p };
```

`authorize[action;resource]` for protected operations. It calls `require[]`, evaluates the policy, and
returns the principal, so there is no need to call `require[]` beforehand:

```q
getTrades:{[s]
  p:.kx.auth.authorize[`read;`data.trades];
  select from trades where sym=s };
```

The resource namespace is **not** the table namespace: the q table is `trades`, its resource is
`data.trades`.

## Obligations — allowing less than was asked

`authorize` answers yes or no. Some entitlement regimes cannot: a market-data licence may permit a query
but only over the last three months, or only for the instruments a subscription covers. The honest answer
there is *"yes, narrowed"*, and `scope` is the verb that can give it.

```q
/ "the narrowing if there is one, else what I asked for" — test MEMBERSHIP, never a null or a fill
narrowed:{[o;k;v] $[k in key o; o k; v]};

ctx:`syms`from`to!(syms; from; to);            / what this request WANTS
o:.kx.auth.scope[`read; `data.trades; ctx];    / signals 'denied, or returns the narrowings
select from trades
  where sym  in    narrowed[o; `syms; syms],
        time within (narrowed[o; `from; from]; narrowed[o; `to; to])
```

An **obligation** is a narrowing of one axis. An absent axis means nothing was narrowed. An **empty**
obligation set is an unconditional allow; an empty narrowing *on an axis* is the opposite — an allow that
yields nothing, never "no constraint".

> **Do not reach for `^` or a null test here.** A missing key on a dict whose values are uniformly typed
> returns a *typed null* — `` o[`syms] `` on a timestamp-valued obligation set is `0Np`, and `0Np ^ syms`
> then signals `'type`. It fails loudly rather than answering wrongly, but the only correct guard is
> `k in key o`. See [q-gotchas.md](../../../../../docs/q-gotchas.md).

### The context is the caller's declaration, and it bounds what a policy may do

**A policy may only narrow an axis the caller declared.** To constrain anything else it must refuse. Two
things follow, and they are the reason the rule is written this way round:

- `authorize` declares no context, but `resources` is always declared implicitly (below), so it CAN be
  handed a `resources` obligation. It refuses one it cannot apply rather than silently narrowing on its
  own behalf, which is what keeps it a boolean verb no matter what policy is installed.
- Declaring more context can only ever *unlock* a narrowing that would otherwise have been a refusal.

`resources` is always declared implicitly — it is the argument — so a policy may always narrow it, and its
obligation is the permitted subset. That is exactly what `entitled` returns, which is why `entitled` is a
shortcut for `scope` rather than a separate mechanism. Narrowing the resource axis to *nothing* is a
refusal, not an allow, so the one-resource and many-resource cases behave the same way.

Context is optional. `(::)` means none declared, and `scope[action;resources;::]` is the simple case.

### Writing a context-aware policy

```q
/ (principal;action;resources;ctx) -> `allowed`obligations[`reason]
entitlements:{[p;a;rs;ctx]
  ok:.kx.rbac.check[p;a;] each rs;
  if[not any ok; :`allowed`obligations!(0b; (`symbol$())!())];
  o:(`symbol$())!();
  if[not all ok; o:o,(enlist `resources)!enlist rs where ok];
  if[not all rs like "kx.*";                              / every resource but the reserved kx.* control plane
    if[not `from in key ctx;                              / it would narrow `from`, which was not declared: refuse
      :`allowed`obligations`reason!(0b; (`symbol$())!(); "declare from: the entitled window starts ",string window)];
    if[ctx[`from] < window; o:o,(enlist `from)!enlist window]];
  `allowed`obligations`reason!(1b; o; "entitled window starts ",string window) };

.kx.auth.setPolicy entitlements;   / same installer, either rank
```

The refusal is what makes the rule hold. Without it, a caller who leaves `from` out gets an unnarrowed
allow and every row before the window. The seam cannot catch that: an allow with no obligation is, by
definition, no constraint. The guard exempts only the reserved `kx.*` control plane, so `bind`, the
assert gate and remote administration, which declare no context, are still decided by capability alone.
Every other resource must declare `from`, whatever it is named, so a copy of this example fails closed
under your own naming. A real deployment can narrow the guard to the resources its window covers.

Three things the seam checks, and one it does not:

| Checked | |
|---|---|
| the obligation's axis was declared | else the caller could not apply it |
| the obligation's q type matches the declared value's, **exactly** | `2026.08.20D09:00:00 > 900000000000` is `1b` — q reads the long as nanos-since-2000, so "clip to 15 minutes" returned as a duration would clip to `2000.01.01D00:15` and pass every row, silently |
| a **list** axis was narrowed, not widened | the return value is authoritative, so a superset would be obeyed |
| *not* checked: that an ordered atom moved the safe way | not decidable without knowing what the axis means, and the seam already trusts the policy to decide at all |

> **Grow an obligation dict with `` o:o,(enlist `k)!enlist v ``.** Not `o,:` and not `` o[`k]: `` — both
> amend a value list q has already narrowed to a single type, and signal `'type` the moment a second axis
> has a different one. Mixed-type obligation sets are the normal case. See
> [q-gotchas.md](../../../../../docs/q-gotchas.md).

### Inspecting a decision instead of obeying it

`explain` answers the same question and *reports* the refusal rather than raising it, so an operator or an
agent can see why:

```q
.kx.auth.explain[principal; `read; `data.trades; (enlist `from)!enlist from]
/ `allowed`obligations`reason`denial!(1b; (,`from)!,2026.05.01D0; "entitled window …"; "")
```

It takes the principal **explicitly**, like `kx.rbac.check` — enforcement reads the principal in effect,
inspection is handed one. That split is deliberate: a caller-supplied subject on an enforcing verb would let
any caller name any principal.

### What the declared path cannot do

`@authorize` carries literal values and `protect` wrappers take only the function's own arguments, so a
declared function **passes no context**: the policy is always called with `ctx` as the empty dictionary
`` (`symbol$())!() ``, never `(::)`, so a policy tests for an axis with `` `from in key ctx `` and never with
`(::)~ctx`, which is always false. Do not protect a function whose data a policy decides on context (an
entitlement window, a symbol or tenant restriction, any other narrowing). Compute the context and call
`scope` explicitly there, and apply what it returns.

If such a function is protected anyway, what happens depends entirely on the policy. One that follows the
rule above, refusing whenever an axis it would narrow is undeclared, makes the function fail closed. One
that allows when the axis is missing is obeyed as written, and the function returns unnarrowed rows. The
seam cannot tell the two apart, because an allow with no obligation is, by definition, no constraint.

## Declared authorization

For a stable grant on a published function, `kx.auth` enforces aimeta's informative `@authorize`
metadata structurally. `protect` wraps the lambda; `loadAnnotations[]` associates the wrapper's token
with the static pair.

> **Declared authorization is capability-only.** A protected call asks the policy one static
> `action resource` question with no context. It suits a function whose answer is yes or no for the whole
> resource. It is the wrong tool for data a policy narrows by entitlement or context; see
> [What the declared path cannot do](#what-the-declared-path-cannot-do).

Constraints: lambdas only, arity 0 to 7, and the wrapper is a `104h` projection. The ceiling is 7
because the projection consumes one of q's eight parameter slots.

Wrappers **fail closed**: a protected function denies until `loadAnnotations[]` has succeeded. A failed
refresh preserves the prior complete snapshot; a successful one replaces it atomically. Declarations are
keyed by token, not by function body, so byte-identical bodies keep distinct declarations.

This delegates through the installed policy, so it works unchanged with any policy implementation.
aimeta is a soft dependency: explicit-only hosts never load it.

Explicit checks stay the right form for private functions and computed resources, and neither form is
a second-class citizen.

## The activation families

There are three independent, idempotent families, and each captures the prior handler at first
activation and **composes** with it rather than clobbering it. A repeated call must not capture the module's own
wrapper as its prior handler.

| Verb | Handlers | Gates |
|---|---|---|
| `activate` | `.z.pw`, `.z.po`, `.z.pc` | Service-account password check and handle lifecycle. No authorization at all. |
| `activateHttp` | `.z.ph`, `.z.pp` | Per-request principal assertion from the `x-kx-principal` header. |
| `activatePerimeter` | `.z.pg`, `.z.ps` | Every remote qIPC message, on `eval` for `kx.q`. |

A bare `use` must never change process behaviour, which is why wiring is a separate explicit call.

`protect` is a fourth, orthogonal family: a per-function wrapper, not a `.z` handler.

**The perimeter gate is coarse by design and never parses the q it gates.** Arbitrary q cannot be mapped
honestly to an action and resource, and a gate that appeared to do so would be worse than none. It is
coarse enough to gate `bind` itself, so an asserter on an armed process also needs `eval` on `kx.q`.

## Behind an HTTP gateway

`activateHttp[]` reads the principal from a case-insensitive `x-kx-principal` header, promotes it, and
scopes it to the request. It is cleared on the way out **and on the error path**.

Two refusals happen before any principal takes effect:

1. **Duplicate headers are refused.** Two headers prove the proxy appended rather than replaced. q
   cannot verify the strip happened, but it can refuse the ambiguity a missing strip produces, rather
   than resolving by first match and binding the client's forged value. This fires even when the proxy
   holds the grant.
2. **The proxy must hold the assert grant**, resolved through the same login map and asking the same
   policy question `bind` asks over qIPC.

`setHttpTrustPerimeter[1b]` lets a deployment that cannot yet map the proxy's login proceed anyway. It
is off by default, consulted only *after* the grant, and audits loudly on every use. Prefer the grant,
because the grant is checkable. The policy will tell you who may assert; perimeter trust will not.

Two operational controls q cannot enforce, and which the deployment must supply: q's HTTP port must be
unreachable except from the proxy, and the proxy must **strip then set** the principal header. Miss the
strip and a client simply sends it. This is the same class of defect as trusting a client-supplied
`X-Forwarded-For`.
