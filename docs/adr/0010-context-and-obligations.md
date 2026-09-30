# ADR 0010: Carry request context on the decision seam, and answer with obligations

## Status

Accepted

## Context

`authorize[action;resource]` answers yes or no. Entitlement regimes that license *part* of a request cannot
use that answer. A market-data subscription may permit a query but only over the last three months, or only
for the instruments it covers; the honest answer is "yes, narrowed", and there was nowhere to put either the
question (a time range is not a subject, an action, or a resource) or the answer.

`entitled[action;resources]` was already returning a narrowing — the permitted subset — which made it the
existing proof that the seam could carry one, and the reason the general form had to subsume it rather than
sit beside it.

Two earlier attempts at the same territory bound the design:

- **[ADR 0003](0003-private-vector-policy.md)** added a private `policyMany` companion so `entitled` could
  evaluate many resources without rescanning the grant table. It was superseded by
  [ADR 0007](0007-peer-auth-rbac-modules.md), and its lifecycle question — *who clears the companion when
  another policy takes ownership?* — is what made it fragile.
- [ADR 0007](0007-peer-auth-rbac-modules.md) then closed the door explicitly: `setPolicy` remained a
  function-only contract.

## Decision

**One decision path with three published arities, and one installer that accepts either rank.**

`scope[action;resources;ctx]` is the general verb: many resources, an optional context in which the caller
declares the axes of its request, and obligations out. `authorize` and `entitled` become shortcuts over it
with unchanged contracts. `explain[principal;action;resources;ctx]` reports the same decision rather than
raising it. `setPolicy` accepts `(principal;action;resource) -> boolean` or
`(principal;action;resources;ctx) -> obligations`, reading the rank once at install time.

**The safety rule: a policy may only narrow an axis the caller declared.** To constrain anything else it must
refuse. The seam additionally requires an obligation to carry the declared value's exact q type, and requires
a list axis to have been narrowed rather than widened.

## Why this succeeds where `policyMany` did not

ADR 0003 answered the many-resource question with a **second slot**, which is what created the lifecycle
problem. This answers it with a **wider argument**: the vector protocol is just a context in which more than
one resource was declared, so there is still exactly one installed thing and nothing to clear. `setPolicy`
keeps sole ownership.

It also does not need a placeholder resource, which is the trap a naive unification falls into: a null
resource means "holds a resource-wildcard grant", not "holds anything", so `check[p;`read;`]` is `0b`. Passing
the vector avoids inventing a sentinel that would have meant the wrong thing.

**The performance motive behind ADR 0003 is not closed for a scalar policy in general.** A plural
request against a rank-3 policy is still N calls with N memo hits — exactly the per-resource loop
`liftScalar` has always run. What is closed is the *contract* question: the seam can now carry a batch,
so an engine that wants to answer one is free to.

> **Note.** `kx.rbac`'s own `policySpec[]` installs at rank 4: its decision does not scale with the
> number of applicable grants, and a plural request is answered in one pass rather than as N calls
> with N memo hits. The paragraph above describes any *rank-3* policy; the shipped reference engine is
> not one.

## Consequences

- **The scalar path is unchanged and pays nothing.** `authorize` under a `setPolicy` boolean policy runs the
  same work it did; the measured single decision stays in the low microseconds.
- **`authorize` refuses an obligation it cannot apply.** It declares no context, but `resources` is always
  declared implicitly, so a partly-satisfied plural request DOES reach it as an obligation rather than an
  obligation being structurally impossible — it fails closed on that obligation rather than silently
  dropping it, which is what lets the boolean verbs stay boolean whatever policy is installed. The rule
  lives in one private helper, `closeDecision`, that both `authorize` and the assert gates' `allows` read.
- **Declaring more context is monotone**: it can only unlock a narrowing that would otherwise have been a
  refusal.
- **The obligation vocabulary is open; the rule is closed.** `kx.auth` defines no axis names beyond
  `resources`, the same posture it takes toward actions. There is deliberately **no axis-kind registry**: the
  seam already trusts the installed policy to decide at all, so machine-checking that a policy does not
  *loosen* a constraint would defend against a threat it does not defend against anywhere else. The type
  check stays because it catches a bug class, not a trust class.
- **A context-aware policy must allow the control-plane triples on an empty context.** `bind`, the HTTP
  assert gate, the perimeter gate and remote administration cannot declare a context; a policy that refuses
  them locks the deployment out of its own repair path. The assert gates go through a rank-agnostic boolean
  helper so a rank-4 policy is not handed a projection.
- **The declared path and the context path are permanently disjoint.** `@authorize` carries literal values,
  so an annotated function cannot supply a context and fails closed under a narrowing policy. Computed axes
  use `scope` explicitly, which is the rule `@authorize` already had for computed resources.
- **No decision is audited.** A narrowing is the decision most likely to be asked about later, but
  logging on the hot path costs the microsecond target. The policy is the audit point.
- **`kx.rbac.explain`, `effective` and `verify` answer for the grant table only**, and are incomplete under a
  narrowing policy. Reaching across the peer boundary to fix that would cost `kx.rbac`'s ability to be
  inspected without `kx.auth` loaded (ADR 0007), so the seam grew its own `explain` instead.
