# kx.auth kdb-x installation

`kx.auth` is written as a module, under kdb-x's module framework. Though modules can be loaded from
anywhere if added to your `$QPATH`, we recommend installing to the `$HOME/.kx/mod/kx` folder. This is to
avoid name clashes with other user defined modules, as well as providing a location for other KX modules
to cross reference each other.

```bash
export QPATH="$QPATH:$HOME/.kx/mod"
mkdir -p ~/.kx/mod/kx/
cp -r modules/kx/auth ~/.kx/mod/kx/
```

For development, symlink instead so edits are live:

```bash
ln -sfn "$PWD/modules/kx/auth" ~/.kx/mod/kx/auth
```

## Bootstrap

Assign the module to the **global** `.kx.auth`. A remote caller's `.kx.auth.bind` has to resolve by
name, so this is a requirement on hosts, not an internal detail.

```q
.kx.auth:use`kx.auth;
.kx.auth.configure[(`svcuser;"service-account-pw")];            / credentials the trusted caller uses
.kx.auth.setLoginGroups[(enlist`svcuser)!enlist`superUsers];    / what groups that LOGIN carries
.kx.auth.setPolicy[{[p;a;r]
  (`superUsers in p`groups) and (a=`assert) and r=`kx.identity}];
.kx.auth.activate[];                                            / wire .z.pw / .z.po / .z.pc
```

`use` on its own is side-effect-free. `activate[]` opts into installing the handlers, composes with any
prior `.z` handler rather than clobbering it, and is idempotent.

**The `setPolicy` grant is required.** `bind` consults this same default-deny policy, so without it
every assertion is refused. The grant is keyed on a **group**, reached through `setLoginGroups`, which
is why there is one grant schema rather than a second subject-keyed one.

A worked grant table lives in
[`demos/local-assertion/host.q`](../../../../demos/local-assertion/host.q).

## Checking it works

```q
q).kx.auth:use`kx.auth
q).kx.auth.setPolicy[{[p;a;r](a=`assert)and r=`kx.identity}]
q).kx.auth.bind[`sub`groups!(`alice;enlist`trader)]
q).kx.auth.current[]`sub
`alice
q).kx.auth.valid[]
1b
```

## Two things worth getting right at install time

**Name a privileged group for a tier, never for a capability.** `superUsers` accumulates grants as
visible rows; `identityAsserters` bakes its one grant into its own name, says the same thing twice, and
can never grow.

**Pick one q-side password verifier.** `configure` is a self-contained development and reference
verifier. Because `activate[]` composes with the prior `.z.pw`, a host may instead leave `configure`
unset and authenticate the service account through an existing `-U` password file or a platform
`.z.pw`. Use one, not both. Whatever process connects needs its own connection-secret source; q's
password file is read by q, never by the caller.

Add the `QPATH` export to your `.bashrc` or equivalent to persist across sessions.
