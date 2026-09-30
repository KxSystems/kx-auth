# ADR 0003: Keep vector policy dispatch private

## Status

Superseded by [ADR 0007](0007-peer-auth-rbac-modules.md)

## Context

`entitled[action;resources]` must evaluate many resources without repeatedly scanning the complete grant
table. Adding a public batch-policy setter would enlarge the authorization contract.

## Decision

The module keeps a private `policyMany` slot. The nested RBAC implementation installs the scalar policy
and then its vector companion. `setPolicy` clears the companion whenever another policy takes ownership.

## Consequences

- The public `setPolicy` and `entitled` signatures remain unchanged.
- Scalar and vector decisions must return equivalent results.
- Replacing a policy cannot leave the previous policy's vector implementation active.
