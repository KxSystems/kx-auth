# How to contribute

Thanks for choosing to contribute to this project.

If you haven't already, read the [README](README.md) and the
[`kx.auth`](modules/kx/auth/README.md) and [`kx.rbac`](modules/kx/rbac/README.md) module references.

## Contributing as a user (non-development)

If you spot a problem, please raise an issue with as much information as possible — the host wiring, the
principal you bound, the policy you installed, and what you expected versus what happened. A
reproducible case, ideally as a few lines that run against `demos/local-assertion/host.q`, is the
fastest path to a fix.

Feature requests can also be raised as issues. Please describe the use case before proposing a new
export or a new configuration knob: this module is deliberately small, and the standing question for
anything new is *can this be expressed as another grant?*

**Security issues are different.** Please do not open a public issue for a way to bypass a gate or to
escalate a principal's reach. Contact the maintainers privately.

## Contributing as a developer

### Getting started

**Set up your environment first.** The demo loads both peer modules through `use`, resolved against
`$QPATH` (default `$HOME/.kx/mod`). Symlink both working directories so edits are live:

```bash
mkdir -p ~/.kx/mod/kx
ln -sfn "$PWD/modules/kx/auth" ~/.kx/mod/kx/auth
ln -sfn "$PWD/modules/kx/rbac" ~/.kx/mod/kx/rbac
```

Then `q tests/test.q` and `bash demos/local-assertion/run.sh` both work against your live edits, from
this directory. You need a licensed `q`; nothing else.

### Making changes

These are contract boundaries; update their documentation with the code:

- **Each module's `export` dict.** Update the corresponding [`kx.auth`](modules/kx/auth/README.md) or
  [`kx.rbac`](modules/kx/rbac/README.md) export table when a name or signature changes.
- **The policy-function contract** accepted by `kx.auth.setPolicy` and returned by `kx.rbac.policy`.
- **The principal shape a policy reads** (`sub`, `client`, `scopes`, `groups`, `aud`, `iss`, `tenant`,
  `exp`, `act`, `claims`) and how promotion derives it. A deployment's policy is written against this.
- **The `assert` / `kx.identity` gating convention** that decides who may assert an identity, and the
  **reserved `kx.*` resource root** it lives under. This is the privilege-escalation primitive in the
  model; changing how it is expressed changes every deployment's policy.
- **The login→groups map** (`setLoginGroups`) and the **subject rule** — a connection's subject is the
  bound principal if one is bound, else the caller's own login. A policy is written against the
  promoted `groups` field either way, and nothing downstream may branch on which path a principal took.

Add or update a test for every behaviour change — see [tests/README.md](tests/README.md), and note the
two conventions it depends on (the module is loaded flat, and a check must **signal** rather than return
a boolean). For anything touching connection or handle lifecycle, add a check to
[`demos/local-assertion/client.q`](demos/local-assertion/client.q) too: it is the only place a real
second socket and a real second login exist.

Default-deny is not negotiable. A change that makes some path allow-by-default, or adds a switch that
does, will be sent back regardless of how convenient it is.

### Continuous integration

Public CI is not provisioned. Before opening a pull request, run both:

```bash
q tests/test.q
bash demos/local-assertion/run.sh
```

Maintainers run the same two before merging.

### Submitting changes

Fork `main` and keep your fork up to date. Open a pull request describing the change **and the reason**.
Reference the relevant issue with `#123`.

For commit messages, prefer "why" over "what". `fix bind` is not enough; `fix bind: a narrower re-bind
merged into the previous principal because the store's values were conforming dicts, so a stale tenant
could reach a policy decision` is.
