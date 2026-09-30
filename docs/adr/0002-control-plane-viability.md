# ADR 0002: Protect control-plane viability

## Status

Accepted

## Context

Once the last `` `assert`kx.identity `` or `` `admin`kx.rbac `` grant is removed, no remote caller can
restore that capability. Bulk replacement and snapshot loading can remove these rows unintentionally.

## Decision

Every operation that can remove grants refuses a transition from at least one holder to no holders for
either capability. A policy that does not yet hold a capability remains mutable so initial configuration
and repair are possible.

## Consequences

- `revoke`, `setGrants`, and `load` cannot remove the final holder of either capability.
- Initial grants may be added in any order.
- The guard also applies to local calls; local code may still modify private state directly when recovery
  is intentional.
