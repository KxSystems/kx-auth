# Architecture decisions

The module's architectural decisions are recorded individually:

- [ADR 0001: Authorize administration by connecting login](adr/0001-login-keyed-administration.md) *(superseded)*
- [ADR 0002: Protect control-plane viability](adr/0002-control-plane-viability.md)
- [ADR 0003: Keep vector policy dispatch private](adr/0003-private-vector-policy.md) *(superseded)*
- [ADR 0004: Expose RBAC as a sub-export](adr/0004-rbac-sub-export.md) *(superseded)*
- [ADR 0005: Fall back to the connecting login](adr/0005-login-subject-fallback.md)
- [ADR 0006: Keep perimeter evaluation coarse](adr/0006-coarse-perimeter-gate.md)
- [ADR 0007: Package auth and RBAC as peer modules](adr/0007-peer-auth-rbac-modules.md)
- [ADR 0008: Authorize administration by current principal](adr/0008-current-principal-administration.md)
- [ADR 0009: Configure the policy-store path locally](adr/0009-configured-policy-store.md)
- [ADR 0010: Carry request context on the decision seam, and answer with obligations](adr/0010-context-and-obligations.md)

Superseded records preserve the earlier rationale; the latest accepted record defines the shipped design.
q-specific implementation constraints are documented separately in [q-gotchas.md](q-gotchas.md).
