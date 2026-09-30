# ADR 0005: Fall back to the connecting login

## Status

Accepted

## Context

kdb+ logins can be assigned groups through `setLoginGroups`. Treating an unbound handle as having no
subject would ignore that local identity and require a second authorization path.

## Decision

The current subject is the request principal, then the bound qIPC principal, then a canonical principal
derived from `.z.u`. Login-derived and asserted principals pass through the same promotion function.

## Consequences

- Unmapped logins have no groups and remain default-deny.
- An unbound handle can exercise grants held by its connecting login.
- Asserter login tiers should not also hold data grants.
- `iss` records provenance for audit but does not alter authorization behavior.
