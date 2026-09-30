# The demo realm

[`realm-kx.json`](realm-kx.json) is imported at container start with `start-dev --import-realm`. Keycloak's
importer rejects unknown fields — including a `_comment` key — so the explanation lives here instead.

The realm is deliberately small. Three things in it are load-bearing:

**1. Realm roles, not groups, and no mapper.** `trader` and `viewer` are *realm roles*, so Keycloak puts
them in the access token's `realm_access.roles` with no protocol mapper configured at all. That path is
already the second entry in `kx.auth`'s default group search order — `groups`, then `realm_access.roles`,
then `roles` — so the q side needs no `setClaims` call either. The gateway's Lua projects them into a flat
`groups` array purely for legibility; either shape promotes to the same principal.

**2. The audience mapper.** Envoy's `jwt_authn` is configured with `audiences: [kdbx]`, and Keycloak would
otherwise mint `aud: account`. The `oidc-audience-mapper` on each client adds `kdbx`. Without it every
request 401s at the gateway with nothing in the logs to say why, which is a long afternoon.

**3. Two clients, one per persona.**

| Client | Type | Flow | Who uses it |
|---|---|---|---|
| `kx-auth-cli` | public | device code (+ direct access grants) | the terminal persona — `kx auth login` |
| `envoy-gateway` | confidential | auth code + PKCE | the browser persona — Envoy's `oauth2` filter |

`directAccessGrantsEnabled` on `kx-auth-cli` is a *test affordance*, not part of the taught topology: it
lets [`checks.sh`](../scripts/checks.sh) mint tokens with one `curl` instead of driving a browser. The
device-code flow the CLI actually implements is exercised for real by
[`login-check.sh`](../scripts/login-check.sh).

## Users

| User | Password | Realm roles | Reaches |
|---|---|---|---|
| `alice` | `alice-demo-pw` | `trader`, `viewer` | `/trades`, `/instruments` — and is refused `/accounts` **by q** |
| `bob` | `bob-demo-pw` | `viewer` | `/instruments` — and is refused `/trades` **by Envoy** |

That last column is the layering: same 403, different enforcer.

## Notes

- `sslRequired: none` because the whole stack is plaintext HTTP on loopback. A deployment terminates TLS at
  the proxy; nothing here should be read as a TLS recommendation.
- Passwords are fixed demo constants that match [`run.sh`](../scripts/run.sh). The Keycloak admin console is at
  http://localhost:8081 with `admin` / `admin` while the stack is up.
- The issuer is pinned to `http://localhost:8081` by `KC_HOSTNAME_URL` in
  [`compose.yaml`](../compose.yaml), because Keycloak otherwise derives it from each request's `Host`
  header and the `iss` claim would stop matching what Envoy is configured to expect.
