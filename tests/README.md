# Tests

```bash
q tests/test.q          # one line per check; exits 0 on green, 1 on any failure
```

Needs a q binary and a license. This in-process suite has no external q dependencies and does not need
the modules installed on the module path (see below). The separate live annotation demo additionally
uses the aimeta module installed with KDB-X.

## Layout

| File | Covers |
|---|---|
| [`test.q`](test.q) | the driver: `runTest` / `summary`, the flat module loads, and the shared `.t.` helpers |
| [`assertion-gate.q`](assertion-gate.q) | `bind` is caller-gated through the same policy — "who may assert" is a grant, not a built-in |
| [`rebind.q`](rebind.q) | per-handle principal replacement and `promote`'s widening behaviour |
| [`login-space.q`](login-space.q) | the login→groups map, the subject rule, and identical login/asserted decisions |

`rbac.q` covers the policy engine, `obligations.q` covers the context axis — the narrowing rule, the
type rule, and that `authorize`/`entitled` do not move at either policy rank — `declared.q` covers
policy-independent aimeta enforcement,
`annotations.q` reads the shipped `.q` and `.md` sources and fails if any `@param` names a parameter
its lambda does not take, and `bench.q` measures decision performance.

## Test conventions

**The modules are loaded flat, and helpers are namespaced.** `test.q` uses `\l` for both module entry
points, rather than `use`, so the private state a regression needs to assert
on — `bound`, `policy`, `claimPaths`, `promote`, `clear`, `logins`, `protect`, `loadAnnotations` — is reachable in the root
namespace. The consequence: an unprefixed test helper can **shadow a module name**, and `clear` really
is a live module verb `rebind.q` calls. So every helper lives under `.t.` (`.t.reset`, `.t.resetLogins`,
`.t.allowAll`, `.t.trap`, `.t.mustDeny`, `.t.mustSignal`, `.t.u`). Note that a flat `\l` and a `use` are
not equivalent loads — the demo under
[`demos/local-assertion`](../demos/local-assertion) proves both deployed namespaces resolve.

**A check passes only when it returns `(::)`.** Assert with `if[cond; '"message"]` and end the body
with `;`. Never return a boolean: a returned `0b` **and** a returned `1b` both FAIL. That is
deliberate: a check must signal rather than report.

`.t.reset[]` empties the per-handle store and restores the default claim paths, so a check that calls
`setClaims` cannot leak into a later one even if it signals partway through. It deliberately does
**not** touch `policy`: "allowed" must never be a default a check inherits silently, so every check
installs the policy it means to test. `.t.resetLogins[]` additionally clears the login map.

**`.t.allowAll[]` is literal allow-all.** Tests that need a narrower policy install one explicitly.

**Some checks are expected to fail.** A check pinning a known, unfixed bug carries a `KNOWN FAILING`
comment naming it, and asserts **the behaviour we want** — so the fix makes it pass. Do not "fix" one by
changing the assertion to match what the code does today; that encodes the bug as the contract. The CLI
suite does the same in each command's owning test module.

## Coverage this suite cannot reach

In-process, `.z.w` is `0i` and `.z.u` is fixed, so the two-handle and different-caller-login properties
are simulated (by driving the store directly, and by granting `assert` to a different login and
confirming refusal). The live versions — a real second connection under a real second login — are
covered by `demos/local-assertion/run.sh`, which is why that demo runs in CI alongside this suite.
