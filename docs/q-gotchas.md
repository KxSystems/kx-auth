# q implementation notes

These q semantics constrain the implementation. Keep their detailed explanations here so runtime source
comments can remain concise.

## Comments

### A solitary `/` silently voids the rest of the file

A bare `/` on its own line opens a **multi-line comment**, terminated only by a solitary `\` or EOF. Every
definition after it vanishes and the file loads with **no error**. Every blank comment line in this repo
therefore carries a trailing `.`:

```q
/ .
```

Check with:

```bash
grep -nE '^[[:space:]]*[/\\][[:space:]]*$' modules/kx/{auth,rbac}/*.q
```

Related: a `/` is only a comment when preceded by whitespace. `];/ x` is **divide**.

## Types and dictionaries

### A dict of conforming dicts becomes a keyed table

Stored directly in the per-handle store, principals make `bound,(enlist w)!enlist principal` merge
rather than replace. A narrower re-bind can retain fields from the previous principal, and a narrower
bind on a second handle can signal `'mismatch`.

So store each principal as a **one-row table** (`enlist enlist p`), which keeps the outer value list
general, and read it back with `first`. `@[d;k;:;v]` and `d[k]:v` merge too; they are **not**
escapes. Assert the invariant directly:

```q
0h = type value bound
```

### Index-assigning a vector into a dict with a uniform typed value list `'type`s

`` p:`sub`iss!(`a;`b) `` has an `11h` value list, so `` p[`groups]:`x`y `` fails — while the same
assignment on a mixed-value dict succeeds. A promotion function therefore works on rich inputs and breaks
on minimal ones.

This is why `promote` leads with a dict **join** (`` p,(enlist `groups)!enlist v ``): the 1-item general
right-hand side forces the result general, making every later assignment safe. Dropping a padding item
does **not** work — q re-types the uniform remainder. `shapeFault`, the check that follows the coercions,
only reads the dict, so it is unaffected.

### `,:` amends a uniform value list in place, so it fails where `,` succeeds

The sibling of the trap above, and the one that bites anything *building* a dict axis by axis:

```q
o:(`symbol$())!();
o,:(enlist `from)!enlist 2026.05.01D0;   / value list is now 12h
o,:(enlist `syms)!enlist `A`B;           / 'type
o:o,(enlist `syms)!enlist `A`B;          / fine
```

`,:` is not `o:o,x`. It amends the existing value list, which q has already narrowed to `12h`, so a
differently-typed value cannot go in. Plain `,` builds a new general list and succeeds. The same applies one
level down: `v,:enlist x` on a list that has gone uniform fails identically.

**A policy returning obligations must therefore grow them with `o:o,(enlist `k)!enlist v`** — never `o,:`
and never `o[`k]:`. Mixed-type obligation sets (a timestamp axis beside a symbol-vector axis) are the normal
case, so this is not an edge.

### The three empty dictionaries are not interchangeable, and comparing two of them *signals*

```q
type key ()!()              / 0h
type key (`symbol$())!()    / 11h
()!() ~ (`symbol$())!()     / 'length  — not 0b
()!() , (enlist `a)!enlist 1   / 'length
```

So an "is this empty" comparison written against the wrong flavour does not answer `0b`, it throws; and
`()!()` cannot be concatenated onto. `kx.auth` pins **one** flavour (`` emptyCtx:(`symbol$())!() ``),
constructs and compares only through it, and normalises any empty dict a caller supplies to it — otherwise
the seam's behaviour would depend on which flavour a caller happened to build.

### A missing key on a general dict returns a *typed empty*, not `(::)`

And *which* empty depends on the dict's value type. So the obvious guard —

```q
v:d`k; if[null v; …]        / WRONG: fails open
```

— is unreliable in both directions. **Test key membership first, and deny first.** In an authorization
path this is the difference between a control and a decoration.

### `x in key d` with a list key goes elementwise on an empty dict

`key ()!()` is `()`, so `` (enlist `traders;`read) in () `` yields `00b`, which `'type`s inside `if`. Once
the dict holds one entry the same expression correctly yields an atom.

A composite-key memo therefore fails **only on the first lookup after each invalidation**, which reads as
intermittent. Test the empty case separately, and with a nested `$[` — not `or`, which is eager (below).

## Evaluation order and eagerness

### `and` / `or` are eager, not short-circuiting

`` (99h=type p) and `groups in key p `` still evaluates `key p` when `p` is `(::)`, and `'type`s. Guard
with a **nested** `$[…;…;…]` instead. In a decision path this matters more than it looks: a path that
*throws* is not a path that *denies*.

### Right-to-left evaluation bites dict lookups in comparisons

```q
e`allowed <> f[x]           / parses as `allowed <> f[x]  -> symbol vs boolean, 'type
(e`allowed) <> f[x]         / correct
```

### A cast before a comparison swallows the comparison

```q
`symbol$() ~ clash          / 'type — parses as `symbol$(() ~ clash), casting a BOOLEAN
(`symbol$()) ~ clash        / what was meant
0 = count clash             / what to write instead
```

Right-to-left means `~` runs first and `` `symbol$ `` is applied to its boolean result. Reaching for a typed
empty literal in a comparison is the usual way in; counting is both shorter and immune.

### A fully-applied projection evaluates at the call site

`trap[{[p] risky p}[path]]` evaluates `risky path` **before** `trap` ever runs, so the signal escapes.
Helpers that trap must be handed a **niladic** lambda.

## Names

### `save` and `load` cannot be assigned in a module body at all

They are q keywords, and the assignment is rejected at **parse** time — which aborts the entire module
load with a bare `'assign`. Not trappable, because the parse never completes.

The peer RBAC module uses niladic `saveTo` / `loadFrom` internally after local `configureStore[path]`.
Export-dict **keys are symbols**, so the public spelling remains `save` / `load`.

`scan` is also reserved; the RBAC narrowing function is named `applicablePaths`.

`show` is likewise reserved at root, which bites throwaway diagnostic scripts.

### `prior` and `next` are reserved as *parameter* names, and fail only at call time

The function loads with no error; **calling** it throws a bare `'nyi`. This is why `serveHttp`'s
prior-handler parameter is `ph`. Ordinary variables like `priorPw` are fine — only the exact token bites.

### A bare symbol literal admits letters, digits, `.` and `_` — not `-`, and no `:`

`` `super-users `` parses as `` `super `` **minus** `users` and errors. A symbol containing `:` likewise
requires construction with `` `$ ``. Module resource paths use literal-safe dotted names.

And juxtaposed symbols separated by *alignment spaces* are **function application**, not a vector:

```q
`traders    `viewers        / 'type
(`traders;`viewers)         / correct
```

The same trap catches a **variable** juxtaposed with a literal: `` .demo.svcUser`padmin `` is *indexing*,
not a 2-item vector.

Resources and verbs are ours to name and stay literal-safe by construction. **Group names are the IdP's**
and may need `` `$"emea-desk-3" `` in a host script.

### `::` defines a *view* at the top level of a script

Inside a lambda, `name::value` is a global assign — which is how this module mutates module-global state.
At the **top level of a script** the same syntax defines a dependency (view) instead, so a diagnostic
script doing `policy::denyAll` silently fails to assign what you meant.

## qSQL

### A qSQL clause cannot see a module-private function

Inside `select` / `exec` / `update` / `delete`, q resolves a name against the table's **columns**, then
the enclosing lambda's **locals and params**, then the **root** namespace. It never reaches the module's
private namespace, so `select from t where privateFn each col` signals `'privateFn`. Locals and params are
fine; *functions* are not.

A flat `\l` puts every module name at root, where the lookup succeeds. The q-native suite therefore cannot
detect this class of error; the module-path demo covers query-bearing exports under `` use`kx.auth ``.

Apply the function outside the query and index with the result:

```q
t where f each t`col          / not: select from t where f each col
```

The demo exercises both modules through `` use`kx.auth `` and `` use`kx.rbac ``, including the engine's
query-bearing verbs, for this reason.

### A nested call in a `where` clause `'rank`s

Even without the namespace problem, `select from t where col in g p` misparses. Resolve into a local
first — which also evaluates it once rather than per row.

## Errors

### A signalled string is truncated at 254 characters

Silently. So a long, carefully-worded error loses precisely its tail, which is where the *what to do about
it* lives. Multi-line signals survive (newlines are preserved), but the byte budget is shared — and
multi-byte characters like an em-dash consume it faster.

Where an error must guide a **remote** caller, keep the signal self-sufficient inside 254 bytes and print
any fuller detail separately. A remote caller only ever receives the signal.

### `ss` and `like` read `[...]` as a character class

So `"policy[]"` is a malformed pattern and `'length`s. Search for `"policy"` instead.

## Interop

### PyKX converts a Python `str` to a q *symbol*

And `list[str]` to a symbol vector, while a unix-epoch number arrives as a q **long**. That is why
`promote` exists at all, why a policy compares claim values as symbols (``` `$x ``` on an already-symbol
value `'type`s), and why `bind` canonicalises `exp` from unix-seconds to a q **timestamp** so it compares
directly to `.z.p`.

### Two one-char strings are a char vector, and one one-char string is a char atom

In q source `("a";"b")` is the char vector `"ab"`, not the general list `.j.k` produces for the JSON
`["a","b"]` — so `promote` symbolises it to `` `ab `` rather than refusing a list-shaped `sub`. And `"c"`
is a char **atom** (`-10h`), which `promote` refuses as a `client`, `iss` or `tenant` where `"cc"` would
be coerced. Neither shape reaches q from JSON or PyKX; only a q caller writing literals hits them.
