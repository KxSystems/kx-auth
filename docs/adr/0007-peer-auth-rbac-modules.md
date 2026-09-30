# ADR 0007: Package auth and RBAC as peer modules

## Status

Accepted

## Context

The nested RBAC implementation shared the `kx.auth` private namespace. Every RBAC name therefore needed
an `rbac` prefix, followed by aliases in a nested export dict. The apparent coupling was largely
incidental: RBAC needs a policy installation protocol, not auth's private implementation.

## Decision

Package `kx.auth` and `kx.rbac` as peer modules with independent namespaces and natural private names.
`kx.rbac.policy[]` returns its decision function; the host passes that function to
`kx.auth.setPolicy`. Loading either module remains side-effect-free.

Remote RBAC administration calls the public `kx.auth.authorize` seam.

## Consequences

- Consumers load and bind `.kx.auth` and `.kx.rbac` separately.
- `kx.auth.setPolicy` remains a function-only contract. Its public decision verbs are unchanged.
- RBAC no longer loads auth as a sibling, reaches into auth-private state, or prefixes private names to
  avoid collisions.
- Deployments using remote RBAC mutations must load `kx.auth`; local RBAC inspection and policy
  evaluation remain usable independently.
