# Changelog

All notable changes to `kx.auth` are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/) and uses
semantic-ish versioning. Pre-1.0: minor bumps may include surface changes.

The top `## [Unreleased]` section is a rolling buffer of in-flight changes. At release time it becomes
`## [X.Y.Z] - YYYY-MM-DD` and a fresh empty section is added above it.

## [Unreleased]

## [0.5.0] - 2026-09-30

First public release. Two peer q modules and a CLI that let a kdb+ process act on behalf of an end user
authenticated upstream, by a trusted gateway, proxy or application, with every decision default-deny.

The version starts at 0.5.0 to match the rest of the `kx-auth` family: the modules, the `kx-auth-cli`
package and `kx-auth-core` share a version number.

### Included

- **`kx.auth`**: identity assertion over qIPC and behind an HTTP gateway, one canonical principal shape
  for both, and the default-deny Subject/Action/Resource seam (`authorize`, `entitled`, and `scope` for
  context and obligations). Also declared enforcement through aimeta `@authorize` annotations and an
  opt-in perimeter gate.
- **`kx.rbac`**: the policy engine behind the seam. One `(grp;act;res)` grant table with segment-wise
  cover, atomic `apply`/`replace` transactions, remote administration, `explain`/`verify`, and
  persistence as native kdb data. A decision costs about 3 µs whatever the policy size, and a
  many-resource request is answered in one pass.
- **The `kx auth` CLI** (`kx-auth-cli` on PyPI): token acquisition, RFC 8693 exchange, identity
  assertion, and `kx rbac` policy administration over qIPC or HTTP.
- **Demos**: a local qIPC walkthrough that runs in one command, and an HTTP topology with Keycloak,
  Envoy and KDB-X in Docker.
- **Agent skills**: guidance for writing policy and operating the CLI.

### Known limitations

- Pre-1.0: the module exports, the principal shape, the grant schema, the store format and the CLI's
  contracts can still change.
- No package distribution: the modules install by copying or symlinking onto the module path.
- The CLI's dependency `kx-auth-core` is a 0.5.0 beta until its final release.
