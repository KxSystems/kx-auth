# `kx.rbac` — RBAC policy for q

`kx.rbac` is the peer policy engine behind [`kx.auth`](../auth/README.md)'s default-deny seam. It keeps
group-keyed grants in one `(grp;act;res)` table and hands its decision function to
`.kx.auth.setPolicy` through `policy[]`.

Loading it does nothing on its own. `kx.auth` refuses every request, including "may this caller assert
an identity", until a host installs a policy.

## API Documentation

* [`kx.rbac` reference](docs/references/rbac.md): the fifteen exports, segment-wise cover and
  wildcards, the atomic `apply` and `replace` transactions, administration, and persistence.

## Installation Documentation

* [Install guide](docs/install.md)

## The model behind it

* [Authorization overview](../../../docs/AUTHORIZATION.md): the vocabulary, the Subject/Action/Resource
  seam, why there is no role entity, and how the two modules fit together.

## Licence

Apache-2.0. See [LICENSE](LICENSE), a copy of the repository's, so the module carries its own terms
when it is copied onto the module path.
