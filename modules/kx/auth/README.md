# `kx.auth` — identity assertion for kdb+

A KDB-X module that lets a kdb+ process act on behalf of an end user whose identity was authenticated
**upstream**, by a trusted gateway, proxy or application, without that user logging into kdb+ at all.

**Two identities.** The connecting process authenticates the *connection* with a service-account login
through `.z.pw`. The end user is **asserted** on that connection afterwards and never logs in. kdb+ does
no token parsing and no crypto: it trusts the assertion because of the connection it arrived on, and
because the asserting login holds a grant saying it may assert.

**One seam, default-deny.** `scope[action;resources;ctx]` is the decision verb — many resources, an optional declared context, and obligations out. `authorize[action;resource]` and `entitled[action;resources]` are its shortcuts for the two dominant cases. `setPolicy` installs the deployment's decision function, at either rank. Until then everything is
refused, including "may this caller assert an identity", which is deliberately just another grant.

## API Documentation

* [`kx.auth` reference](docs/references/auth.md): the eighteen exports, the principal shape, the subject
  rule, the reserved resource root, declared authorization, and the activation families.

## Installation Documentation

* [Install guide](docs/install.md)

## The model behind it

* [Authorization overview](../../../docs/AUTHORIZATION.md): the vocabulary, the
  Subject/Action/Resource seam, the supported topologies, and what q cannot enforce.

## Policy modules

`kx.auth` holds no policy of its own. [`kx.rbac`](../rbac/README.md) is the peer engine that supplies
one; a host may install any other function of the same shape.

## Licence

Apache-2.0. See [LICENSE](LICENSE), a copy of the repository's, so the module carries its own terms
when it is copied onto the module path.
