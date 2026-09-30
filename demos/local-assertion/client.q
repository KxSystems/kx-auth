/ local-assertion demo client — the trusted intermediary, over REAL qIPC.
/ .
/ Stands in for an application server or gateway: it authenticates as the service account, asserts an end user's identity by
/ binding a principal to its own connection, and then calls the host's gated verbs on that user's
/ behalf. Nothing here parses a token — the point of the thin model is that the terminus already did.
/ .
/ This exercises the three properties the in-process suite CANNOT reach, because in-process .z.w is 0i
/ and .z.u is fixed:
/   - a REAL second login (`intruder`) that authenticates fine but holds no `assert grant is refused;
/   - TWO real handles hold independent principals, and a bind on one does not disturb the other;
/   - a narrower re-bind on a live handle replaces the principal wholesale.
/ .
/ Run by run.sh, which starts the host and passes the port + passwords through the environment.
/ Exits 0 when every check passes, 1 if any failed.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ ---- a tiny check harness (this file is standalone — it does not load tests/test.q) ---------------
.c.fails:0;
.c.check:{[name;fn]
  e:@[{[g] g[]; `ok}; fn; {x}];
  $[`ok~e;
    -1 "  ok    ",string name;
    [-2 "  FAIL  ",(string name)," - ",$[10h=type e; e; -3!e]; .c.fails+:1]]; };

/ Expect a call to be refused with a 'denied that NAMES the expected gate — so a capability denial and
/ a data denial can never be conflated, which is the whole point of having two sets.
.c.deny:{[h;call;what]
  e:@[h; call; {x}];
  if[not 10h=type e; '"expected a 'denied signal, got: ",-3!e];
  if[not "denied"~6#e; '"expected 'denied, got: ",e];
  if[not count e ss what; '"denied by the wrong gate — wanted \"",what,"\", got: ",e]; };

/ ---- connect --------------------------------------------------------------------------------------
.c.env:{[k;d] $[count v:getenv k; v; d]};
.c.port:.c.env[`DEMO_PORT; "5011"];
.c.dial:{[u;pw] hopen `$":localhost:",.c.port,":",u,":",pw};

h1:.c.dial["kxmcp"; .c.env[`DEMO_SVC_PW; "s3cret-svc-pw"]];    / the terminus, handle 1 (acts for alice)
h2:.c.dial["kxmcp"; .c.env[`DEMO_SVC_PW; "s3cret-svc-pw"]];    / the terminus, handle 2 (acts for bob)
-1 "connected as kxmcp on two handles (:",.c.port,")";
-1 "";

/ The end users the terminus asserts. Group membership is what every grant keys on: alice holds both
/ groups, bob only `viewer, carol none at all.
.c.alice:`sub`groups`tenant!(`alice;`viewer`trader;`acme);
.c.bob  :`sub`groups!(`bob; enlist `viewer);
.c.carol:(enlist `sub)!enlist `carol;

/ ---- 1. an unbound handle is refused, even though it is authenticated -----------------------------
/ The connection cleared the password gate. That buys nothing: with no principal bound, a gated verb
/ must refuse rather than run with the service account's own reach.
/ .
/ WHY the denial now names the data grant rather than "no principal bound": under the subject rule an
/ unbound handle decides as the CALLER'S OWN LOGIN, so `kxmcp` is the subject and the refusal comes from
/ the data gate finding no `read on `data.trades grant for its groups. The posture is unchanged and this
/ is the more valuable assertion: it proves the service account's own login — which DOES hold a grant,
/ `assert on `kx.identity — gains no data reach from it. Keeping the asserter's tier to control-plane
/ grants only is what makes the fallback inert.
.c.check[`unboundHandleDenied; {[]
  .c.deny[h1; (`.demo.getTrades;`AAPL); "read on data.trades"]; }]

/ ---- 2. the terminus asserts alice, and her grants take effect ------------------------------------
.c.check[`aliceBindsAndReads; {[]
  h1(`.kx.auth.bind; .c.alice);
  r:h1(`.demo.getTrades;`AAPL);
  if[not 2=count r; '"expected 2 AAPL rows, got ",string count r]; }]

.c.check[`aliceWriteAllowed; {[]
  before:count h1(`.demo.getTrades;`AAPL);
  h1(`.demo.addTrade; `time`sym`side`price`size!(.z.p;`AAPL;`B;188.5;10));
  if[not before+1 = count h1(`.demo.getTrades;`AAPL); '"the write did not land"]; }]

/ No verb implies another: alice holds read AND write rows, and holds no delete row.
.c.check[`aliceDeleteDenied; {[]
  .c.deny[h1; ".demo.dropTrades[]"; "delete on data.trades"]; }]

.c.check[`aliceClearsCapabilityAndData; {[]
  r:h1(`.demo.sqlTool;`MSFT);
  if[not 2=count r; '"expected 2 MSFT rows through the tool, got ",string count r]; }]

.c.check[`aliceRunsDeclaredAnalytic; {[]
  r:h1(`.demo.tradeSummary;`AAPL);
  if[not 1=count r; '"expected one AAPL aggregate row, got ",string count r];
  if[((first value r)`totalSize)<>230; '"the declared analytic returned the wrong total size: ",-3!r];
  }]

/ ---- 3. THE HEADLINE: bob clears the capability check and is stopped by the data gate -------------
.c.check[`bobBindsOnSecondHandle; {[]
  h2(`.kx.auth.bind; .c.bob);
  if[not `bob ~ (h2 ".demo.whoami[]")`sub; '"bob is not the principal in effect on handle 2"]; }]

/ The denial names "read on data.trades", NOT "query on kdbx.sql" — so the capability check PASSED and
/ the data gate is what refused. Two independent sets, one engine.
.c.check[`bobPassesCapabilityFailsDataGate; {[]
  .c.deny[h2; (`.demo.sqlTool;`AAPL); "read on data.trades"]; }]

/ ... and a principal with no groups at all is stopped EARLIER, by the capability check.
.c.check[`grouplessPrincipalDeniedAtCapability; {[]
  h2(`.kx.auth.bind; .c.carol);
  .c.deny[h2; (`.demo.sqlTool;`AAPL); "query on kdbx.sql"];
  h2(`.kx.auth.bind; .c.bob); }]                             / put bob back for the checks below

/ ---- 4. two real handles, two independent principals ---------------------------------------------
/ In-process this can only be simulated by driving the store; here handle 1 really is a second socket.
.c.check[`twoHandlesStayIndependent; {[]
  if[not `alice ~ (h1 ".demo.whoami[]")`sub; '"handle 1 lost alice when handle 2 bound someone else"];
  if[not 2=count h1(`.demo.getTrades;`MSFT); '"handle 1 stopped reading after handle 2 re-bound"]; }]

/ ---- 5. a narrower re-bind on a live handle replaces the principal wholesale ----------------------
.c.check[`rebindReplacesWholesaleOverIpc; {[]
  if[not `acme ~ (h1 ".demo.whoami[]")`tenant; '"precondition failed: alice's tenant was not bound"];
  h1(`.kx.auth.bind; `sub`groups!(`alice;`viewer`trader));    / a refreshed token, with no tenant claim
  if[`tenant in key h1 ".demo.whoami[]"; '"a stale tenant survived a narrower re-bind over IPC"]; }]

/ ---- 6. entitled[] scopes down in one round-trip, instead of probing for denials ------------------
/ It answers in RESOURCE paths, not table names — the resource namespace is not the table namespace.
.c.check[`entitledScopesDownPerPrincipal; {[]
  a:h1 ".demo.listTables[]";
  if[not `data.instruments`data.trades ~ asc a; '"alice should see both tables, saw ",-3!a];
  b:h2 ".demo.listTables[]";
  if[count b; '"bob should see no readable tables, saw ",-3!b]; }]

/ ---- 7. authenticated is NOT permitted to assert -------------------------------------------------
/ `intruder` is a real login in the same -U file: it clears the password gate exactly as the service
/ account does. It holds no `assert grant, so bind[] refuses it. This is what makes "who may assert" a
/ policy grant keyed on .z.u rather than a trust-the-connection assumption.
.c.check[`authenticatedIntruderCannotAssert; {[]
  h3:.c.dial["intruder"; .c.env[`DEMO_INTRUDER_PW; "s3cret-intruder-pw"]];
  .c.deny[h3; (`.kx.auth.bind; .c.alice); "not permitted to assert"];
  hclose h3; }]

/ protect[] changes local module state and is therefore a startup-only operation, not an RPC surface.
.c.check[`remoteProtectDenied; {[]
  hp:.c.dial["padmin"; .c.env[`DEMO_PADMIN_PW; "s3cret-padmin-pw"]];
  e:@[hp; (`.kx.auth.protect; {[x] x}); {x}];
  if[not 10h=type e; '"remote protect did not signal"];
  if[not count e ss "local calls only"; '"remote protect signalled the wrong reason: ",e];
  hclose hp; }]

/ ---- 8. the engine's administration surface, over a REAL connection -------------------------------
/ Everything below is reachable only here. Two reasons, and the second is the one that bites:
/ .
/   - the admin gate distinguishes REMOTE from local callers (.z.w=0 bypasses it), so in-process tests
/     structurally cannot exercise the remote half;
/   - the engine's query-bearing verbs behave DIFFERENTLY under `use` than under the suite's flat `\l`.
/     A qSQL clause cannot resolve a namespace-private function, and a flat load hides that by putting every
/     name at root. explain / setGrants / effective are exercised here for exactly that reason — this is
/     the only place a regression of that class can be caught.
.c.padmin:.c.env[`DEMO_PADMIN_PW; "s3cret-padmin-pw"];

.c.check[`remoteMutationDeniedWithoutAdminGrant; {[]
  / Alice is the principal in effect and holds no `admin grant.
  .c.deny[h1; (`.kx.rbac.grant;`trader;`delete;`data.trades); "admin on kx.rbac"];
  .c.deny[h1; ".kx.rbac.save[]"; "admin on kx.rbac"]; }]

.c.check[`remoteMutationAllowedWithAdminGrant; {[]
  hp:.c.dial["padmin"; .c.padmin];
  n:hp(`.kx.rbac.grant;`viewer;`read;`data.instruments);
  if[not 9=n; '"expected 9 grants after the addition, got ",string n];
  hp(`.kx.rbac.revoke;`viewer;`read;`data.instruments);
  hclose hp; }]

/ The host chooses the path during local bootstrap. Even an administrator may only operate that store,
/ never redirect persistence to another filesystem target.
.c.check[`remoteStoreConfigurationDenied; {[]
  hp:.c.dial["padmin"; .c.padmin];
  e:@[hp; (`.kx.rbac.configureStore; "/tmp/not-the-configured-store"); {x}];
  if[not 10h=type e; '"remote configureStore did not signal"];
  if[not count e ss "local calls only"; '"remote configureStore signalled the wrong reason: ",e];
  hclose hp; }]

.c.check[`remoteMutationPersistsWithSaveLoad; {[]
  hp:.c.dial["padmin"; .c.padmin];
  hp(`.kx.rbac.grant;`viewer;`read;`data.instruments);
  hp ".kx.rbac.save[]";
  hp(`.kx.rbac.revoke;`viewer;`read;`data.instruments);
  if[not 8=count hp ".kx.rbac.grants[]"; '"the live revoke did not take effect before reload"];
  hp ".kx.rbac.load[]";
  if[not 9=count hp ".kx.rbac.grants[]"; '"load did not restore the saved remote mutation"];
  hp(`.kx.rbac.revoke;`viewer;`read;`data.instruments);  / restore the declared baseline
  hclose hp; }]

/ The policy administrator's direct principal holds no assertion grant.
.c.check[`policyAdminMayNotAssert; {[]
  hp:.c.dial["padmin"; .c.padmin];
  .c.deny[hp; (`.kx.auth.bind; .c.alice); "not permitted to assert"];
  hclose hp; }]

/ An asserted principal uses the same authorization path as a direct principal.
.c.check[`assertedAdminMayMutatePolicy; {[]
  h1(`.kx.auth.bind; `sub`groups!(`escalator; enlist `policyAdmins));
  if[not `escalator ~ (h1 ".demo.whoami[]")`sub; '"the administrator-group principal was not bound"];
  n:h1(`.kx.rbac.grant;`viewer;`read;`data.instruments);
  if[not 9=n; '"the asserted administrator could not add a grant"];
  h1(`.kx.rbac.revoke;`viewer;`read;`data.instruments);
  h1(`.kx.auth.bind; .c.alice); }]                                     / restore alice for what follows

/ explain is the agent-facing verb: a denial that names the missing grant, not just "denied". This also
/ exercises a qSQL path that only fails under `use`.
.c.check[`explainNamesTheMissingGrantOverIpc; {[]
  r:h1(`.kx.rbac.explain; .c.bob; `read; `data.trades);
  if[r`allowed; '"explain claimed bob may read trades"];
  if[not "read:data.trades" ~ r`pair; '"explain's display pair is wrong: ",-3!r`pair];
  if[not count (r`reason) ss "no "; '"explain gave no usable reason: ",r`reason];
  / ... and it agrees with the gate that actually refused
  a:h1(`.kx.rbac.explain; .c.alice; `read; `data.trades);
  if[not a`allowed; '"explain disagreed with alice's working read grant"]; }]

/ effective and grants[] are read-side: no admin grant needed, and both cross the same `use` boundary.
.c.check[`readSideVerbsNeedNoAdminGrant; {[]
  g:h1 ".kx.rbac.grants[]";
  if[not 8=count g; '"expected 8 declared grants, got ",string count g];
  if[not `grp`act`res ~ cols g; '"grants[] leaked the derived seg column"];
  e:h1(`.kx.rbac.effective; .c.alice);
  if[not 6=count e; '"alice's effective set should be 6 rows (viewer+trader), got ",string count e]; }]

/ A malformed replacement must fail and leave the live set untouched.
.c.check[`setGrantsValidatesAndPreservesOverIpc; {[]
  hp:.c.dial["padmin"; .c.padmin];
  before:hp ".kx.rbac.grants[]";
  .c.deny2:{[h;call;what]
    e:@[h; call; {x}];
    if[not 10h=type e; '"expected a signal, got: ",-3!e];
    if[not count e ss what; '"wrong error — wanted \"",what,"\", got: ",e]; };
  .c.deny2[hp; (`.kx.rbac.setGrants; ([] grp:enlist `g; act:enlist `read; res:enlist `data..bad)); "malformed resource path"];
  .c.deny2[hp; (`.kx.rbac.setGrants; ([] grp:`g`g; act:`read`read; res:`data.x`data.x)); "duplicate grant row"];
  if[not before ~ hp ".kx.rbac.grants[]"; '"a failed setGrants disturbed the live grant set"];
  hclose hp; }]

/ THE PAYOFF: an administrator changes the policy over a live connection and the decision changes with no
/ reload. This is the failure mode the whole administration surface exists to avoid — edit-a-file-then-
/ reload, where an agent cannot see the effect of its own change.
.c.check[`aGrantTakesEffectLiveWithNoReload; {[]
  .c.deny[h1; ".demo.dropTrades[]"; "delete on data.trades"];      / denied now ...
  hp:.c.dial["padmin"; .c.padmin];
  hp(`.kx.rbac.grant;`trader;`delete;`data.trades);
  h1 ".demo.dropTrades[]";                                          / ... allowed immediately after
  if[count h1(`.demo.getTrades;`AAPL); '"the delete did not take effect"];
  hp(`.kx.rbac.revoke;`trader;`delete;`data.trades);
  .c.deny[h1; ".demo.dropTrades[]"; "delete on data.trades"];      / ... and denied again after revoke
  hclose hp; }]

/ ---- report --------------------------------------------------------------------------------------
hclose h1; hclose h2;
-1 "";
$[.c.fails=0;
  [-1 "ALL PASS"; exit 0];
  [-1 (string .c.fails)," CHECK(S) FAILED"; exit 1]];
