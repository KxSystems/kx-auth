# ADR 0009: Configure the policy-store path locally

## Status

Accepted

## Context

Remote administrators need to persist live grant changes. Allowing them to supply a filesystem path to
`save` or `load` would also let them select arbitrary process-readable or process-writable files, and a
shell-based atomic rename would turn an unquoted path into command execution.

## Decision

The host calls `configureStore[path]` locally during bootstrap. Remote calls to that verb are refused.
`save[]` and `load[]` accept no path and use the configured store through the ordinary `admin:kx.rbac`
gate. Authorization occurs before filesystem access.

## Consequences

- A remote administrator can make live mutations durable with `grant[]` / `revoke[]`, then `save[]`.
- Remote callers cannot redirect persistence to another path.
- `load[]` remains available remotely for deliberate rollback to the configured snapshot.
- A host that wants persistence must configure the path explicitly at startup.
