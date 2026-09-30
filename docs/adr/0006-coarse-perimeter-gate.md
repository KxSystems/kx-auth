# ADR 0006: Keep perimeter evaluation coarse

## Status

Accepted

## Context

Arbitrary q messages cannot be mapped reliably to one `(action;resource)` pair. Partial parsing would
present an authorization boundary that does not cover the language it accepts.

## Decision

`activatePerimeter[]` requires a valid subject with `` `eval `` on `` `kx.q `` and then delegates the
message unchanged to the prior `.z.pg` or `.z.ps` handler.

## Consequences

- The perimeter gate is an opt-in capability check, not statement-level authorization.
- The module does not inspect or rewrite q messages.
- Hosts requiring finer controls must expose constrained verbs and authorize those verbs directly.
