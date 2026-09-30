# ADR 0001: Authorize administration by connecting login

## Status

Superseded by [ADR 0008](0008-current-principal-administration.md)

## Context

A login permitted to assert identity can bind a principal with any group membership. Authorizing policy
administration against that bound principal would therefore let the asserter manufacture its own
administrator.

## Decision

Remote RBAC mutations authorize `loginPrincipal .z.u` for `` `admin `` on `` `kx.rbac ``. They never use
the bound principal. `bind` may accept principals whose groups hold administrative grants.

## Consequences

- An asserted administrator group cannot confer administration on its caller.
- Audit records identify the connecting login.
- Assertion and administration should be assigned to separate login tiers.
- A wildcard grant does not prevent a principal from being bound.
