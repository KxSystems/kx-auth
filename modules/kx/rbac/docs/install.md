# kx.rbac kdb-x installation

`kx.rbac` is written as a module, under kdb-x's module framework. Though modules can be loaded from
anywhere if added to your `$QPATH`, we recommend installing to the `$HOME/.kx/mod/kx` folder. This is to
avoid name clashes with other user defined modules, as well as providing a location for other KX modules
to cross reference each other.

`kx.rbac` is a peer of [`kx.auth`](../../auth/README.md) rather than a dependency of it, but it has
nothing to plug into on its own. Install both.

```bash
export QPATH="$QPATH:$HOME/.kx/mod"
mkdir -p ~/.kx/mod/kx/
cp -r modules/kx/auth ~/.kx/mod/kx/
cp -r modules/kx/rbac ~/.kx/mod/kx/
```

Now from anywhere you can import the modules, declare grants, and install the decision function.

```q
q).kx.auth:use`kx.auth
q).kx.rbac:use`kx.rbac
q).kx.rbac.grant[`trader;`read;`data.trades]
1
q).kx.auth.setPolicy .kx.rbac.policy[]
q).kx.rbac.check[`sub`groups!(`alice;enlist`trader);`read;`data.trades]
1b
q).kx.rbac.check[`sub`groups!(`bob;enlist`viewer);`read;`data.trades]
0b
```

`check` takes its principal as an argument and touches no connection state, so a q process with the
module loaded is already a policy service.

Two grants are worth declaring before anything else, because the policy engine warns when they are
missing: `assert` on `kx.identity` decides who may assert an identity at all, and `admin` on `kx.rbac`
decides who may change the policy remotely.

```q
q).kx.rbac.grant[`superUsers;`assert;`kx.identity]
2
q).kx.rbac.grant[`policyAdmins;`admin;`kx.rbac]
3
q).kx.rbac.report[0b]
kx.rbac.verify: no issues.
severity issue detail
---------------------
```

To persist grants across restarts, configure a store from local startup code. Remote callers cannot
choose a filesystem path.

```q
q).kx.rbac.configureStore "/etc/kx/grants"
`:/etc/kx/grants
```

Add the `QPATH` export to your `.bashrc` or equivalent to persist across sessions.
