# ADR 0008: Authorize administration by current principal

## Status

Accepted

## Context

Identity assertion delegates the principal and its group claims to a trusted asserter. Treating an
asserted principal as valid for data access but categorically invalid for policy administration adds a
second trust rule to the authorization seam.

The authority to call `bind` is different: it must be checked against the connecting login because no
asserted principal exists yet.

## Decision

Remote RBAC mutations call `kx.auth.authorize[admin;kx.rbac]` and therefore authorize the principal in
effect: the bound principal when present, otherwise the connecting login's canonical principal.

## Consequences

- Direct and asserted principals use the same policy checks for RBAC administration.
- A trusted asserter can assert an administrator group, just as it can assert any other privileged group.
- Only identity assertion selects the connecting login explicitly, during the pre-bind check.
- Audit records identify both the effective principal and the connecting login.
