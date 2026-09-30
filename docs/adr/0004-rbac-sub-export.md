# ADR 0004: Expose RBAC as a sub-export

## Status

Superseded by [ADR 0007](0007-peer-auth-rbac-modules.md)

## Context

The RBAC engine needs the private `policy`, `setPolicy`, and `promote` functions from `kx.auth`.

## Decision

`rbac.q` loads into the same module namespace as `init.q` and is exposed through the nested `rbac` export
dict. Private engine names use the `rbac` prefix.

## Consequences

- Consumers call `.kx.rbac.<verb>` locally or over qIPC.
- `save` and `load` remain public dict keys while their private functions use assignable q names.
- The flat-loading test suite loads `rbac.q` before `init.q`; module loading resolves it as a sibling.
