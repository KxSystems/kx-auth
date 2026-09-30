---
name: kx-auth-cli
description: Operate KX identity assertion and kx.rbac policy from the fastmcp-free `kx` CLI. Use when choosing among login, introspect, exchange, assert, and rbac commands; chaining workload or interactive credentials into q; inspecting/explaining grants; applying atomic policy changes; importing/exporting JSON or CSV; handling promoted principals; or branching on CLI exit codes.
---

# Operate KX authorization from the CLI

Keep authentication and policy input distinct. A bearer or qIPC login authenticates a caller;
`--principal` only models a subject for a pure decision.

## Choose the path

- For workload/CI identity, exchange the platform token, extract `result.access_token` from the
  envelope, then assert it over qIPC. Do not pipe the whole exchange envelope into `assert`.
- For an operator reaching a bare q host, use `kx rbac ... --connect HOST:PORT`. The qIPC login is the
  subject, so no OAuth login is required.
- For an interactive user behind an OAuth-aware gateway, run `kx auth login --server URL`, then
  `kx rbac ... --server URL`. The second command reuses the endpoint-keyed cached bearer.

```bash
export KX_AUTH_TOKEN="$(platform-token \
  | kx auth exchange --audience kdbx --token-url https://idp/token --json \
  | jq -r .result.access_token)"
kx auth assert --connect kdb:5010 --user svcuser --json
```

Token-source precedence is explicit argument, piped stdin, environment, then cache where supported.
An `assert` without `--connect` is only an indicative projection; q's `promoted` readback is the policy
principal. To reuse that exact subject in a later decision:

```bash
kx auth assert --token "$TOKEN" --connect kdb:5010 --promoted-out principal.json --json
kx rbac check read:data.trades --principal @principal.json --connect kdb:5010 --json
```

The principal file cannot authorize a mutation.

## Inspect and change policy

Use `show`, `check`, `explain`, and `verify` freely within an authenticated transport. Prefer `explain`
when a denial needs a reason. q requires `admin:kx.rbac` for `grant`, `revoke`, committed imports,
`save`, and `load`.

```bash
kx rbac show --connect kdb:5010 --json
kx rbac show --principal @promoted.json --connect kdb:5010 --json
kx rbac explain read:data.accounts --server https://gateway.example --json
kx rbac verify --connect kdb:5010 --json
kx rbac grant trader read:data.trades --server https://gateway.example --json
```

`show --principal` answers "what does this subject hold" through the engine's own `effective`. Use it
instead of reading the whole table and matching groups yourself; group membership is q's to decide.

`verify` runs the policy lint. It answers a different question from the transaction guard: a commit is
refused only when it would remove the last holder of `assert:kx.identity` or `admin:kx.rbac`, so a
total wildcard or an asserter tier that also holds data grants commits like anything else. Run `verify`
after building a policy up from empty, after `load`, and before declaring a deployment ready.

Changes persist atomically by default. There is no CLI `apply`, `--no-save`, or separate merge mode:

- Import ordered `operations` for merge/update behavior.
- Import a full `grants` snapshot only with `--replace`.
- Run `import --dry-run` to get q's candidate diff and findings before committing.
- Treat operations as idempotent patches. An absent revoke succeeds with `changed=false`; inspect the
  acknowledgement instead of retrying it as an error.
- Treat `import --replace` as authoritative for the complete policy and review its full diff carefully.
- Use JSON `null` or CSV `*` for action/resource wildcards. Never omit a field to imply a wildcard.

## Branch on the contract

Use `--json` and the exit code, not message text:

- `0`: ok or allowed
- `1`: operational or server error
- `2`: usage or invalid input
- `3`: authentication required or cached login expired; run `kx auth login` for the gateway
- `4`: valid caller, policy denied

`verify --fail-on error|warning` exits `1` when a finding at that severity or worse is present, and
keeps the findings in `result` so they can be reported. It is `1` and not `4`: nothing was denied, the
policy is simply not in a state the caller accepted. Without `--fail-on`, `verify` always exits `0`.

Keep passwords in `$KX_AUTH_KDB_PASSWORD`, not command history. Never disable TLS verification outside
development. `kx rbac check` is the q engine's decision; there is no `kx auth check`.
