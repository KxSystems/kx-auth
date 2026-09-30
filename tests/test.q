/ tests/test.q — the kx.auth test driver. Run from `public/`:
/ .
/     q tests/test.q            / prints one line per check; exits 0 on green, 1 on any failure
/ .
/ The module is loaded FLAT (\l), not via `use`kx.auth`, so the private state the suites assert on
/ (`bound`, `policy`, `claimPaths`, `promote`, `clear`, `protect`, `loadAnnotations`) is reachable in the root namespace. That is a
/ deliberate divergence from how a host loads the module, and it is exactly why every helper below is
/ namespaced under `.t.`: an unprefixed helper would shadow a module name, and `clear` really is a live
/ module verb one of the suites calls. Also at root after the load: bound policy promote shapeFault dig
/ canon asSym asSyms bind current valid require closeDecision allows authorize entitled svc priorPw pwCheck
/ fromJson serveHttp export.
/ .
/ A check PASSES only when its lambda returns (::) — i.e. its body ends with ";". Assert with
/ `if[cond; '"message"]` and never return a boolean: a returned 0b AND a returned 1b both FAIL. That
/ is the point: a check must signal rather than report.
/ .
/ NB a solitary "/" line would open a block comment and silently void the rest of the file, so every
/ blank comment line here carries a trailing ".".

results:()

runTest:{[name; fn]
  err:@[fn; ::; {x}];
  pass:(::)~err;
  errStr:$[pass; ""; $[10h = type err; err; -3!err]];
  results,::enlist (name; pass; errStr);
  $[pass;
    -1 "  ok    ", string name;
    -2 "  FAIL  ", (string name), " - ", errStr];
  }

summary:{[]
  fails:count results where not results[;1];
  -1 "";
  -1 "ran ", (string count results), " tests, ", (string fails), " failed";
  exit fails > 0
  }

/ Load both peer modules flat so tests can inspect private state. Publish the auth export at `.kx.auth`
/ because kx.rbac's temporary administration bridge resolves it there, as production does.
\l modules/kx/auth/init.q
.kx.auth:export;
\l modules/kx/rbac/init.q

/ ---- shared helpers — ALL under .t. (see the header) ---------------------------------------------
/ The in-process caller login. bind[] passes this to the policy as the subject's `sub, so a check that
/ wants "the caller may assert" grants it to .t.u.
.t.u:.z.u;

/ Restore the module to a pristine state between checks: empty the whole per-handle store (any handle)
/ and put the claim paths back to their defaults, so a check that calls setClaims cannot leak into a
/ later one even if it signals partway through. Deliberately does NOT touch `policy` — "allowed" must
/ never be a default a check inherits silently; every check installs the policy it means to test.
.t.reset:{[] bound::(`int$())!(); claimPaths::`groups`tenant!("";"tenant"); };

/ Allow everything, including `assert. Used by tests that do not exercise the gate.
.t.allowAll:{[] setPolicy[{[p;a;r] 1b}]; };

/ Install the peer engine through the public policy protocol. `policySpec[]` is now the rank-4
/ `decideMany`, so this checks the installed function and rank rather than an exact identity.
.t.installRbac:{[] setPolicy policySpec[]; };
.t.rbacPolicyActive:{[] (policy~decideMany) and 4=policyRank};

/ Run a niladic lambda, returning `ok on success or the signalled error.
.t.trap:{[f] @[{[g] g[]; `ok}; f; {x}]};

/ Assert that a lambda is refused with a 'denied signal (the module's default-deny posture).
.t.mustDeny:{[f]
  e:.t.trap f;
  if[not $[10h = type e; "denied" ~ 6#e; 0b]; '"expected a 'denied signal, got: ", -3!e]; };

/ Assert that a lambda signals, and that the message NAMES the expected reason — so two different
/ refusals can never be conflated by a check that only asked "did it fail". Use this over .t.mustDeny
/ wherever more than one gate could plausibly have fired.
.t.mustSignal:{[f;what]
  e:.t.trap f;
  if[not 10h = type e; '"expected a signal, got: ", -3!e];
  if[not count e ss what; '"signalled for the wrong reason — wanted \"",what,"\", got: ",e]; };

/ ---- the suites ----------------------------------------------------------------------------------
system "l tests/assertion-gate.q";
system "l tests/rebind.q";
system "l tests/login-space.q";
system "l tests/rbac.q";
system "l tests/declared.q";
system "l tests/annotations.q";
system "l tests/perimeter.q";
system "l tests/obligations.q";
system "l tests/bench.q";

summary[]
