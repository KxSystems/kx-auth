/ tests/rbac.q — the kx.rbac policy engine: the cover relation, the wildcard, the absence of verb
/ subsumption, structural validation, and the default-deny failure modes.
/ .
/ Every check here pins a decision the design argues for, so weakening one fails a test rather than
/ passing review. The two that matter most:
/   - COVER IS SEGMENT-WISE, NOT STRING PREFIX. `data.trades` must not cover `data.tradesecret`, and
/     `data` must not cover `datastore.x`. A naive (string r) like (string g),"*" returns 1b for both.
/   - NO VERB SUBSUMPTION. A `write grant does not confer `read, ever.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ Start from an empty grant set without changing kx.auth's installed policy.
.t.resetRbac:{[] grantStore::presplit ([] grp:`symbol$(); act:`symbol$(); res:`symbol$()); storePath::(::); .t.reset[]; };

/ A subject holding exactly these groups. Not promoted — the engine must cope with whatever a caller
/ hands it, which is also what `check`'s explicit-principal form will be handed.
.t.subj:{[gs] `sub`groups!(`testuser; (),gs)};

/ ---- 1. the cover relation ------------------------------------------------------------------------
runTest[`coverIsSegmentwiseNotStringPrefix; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  t:.t.subj[`traders];
  if[not decide[t;`read;`data.trades];       '"a grant did not cover its own exact resource"];
  if[not decide[t;`read;`data.trades.price]; '"a grant did not cover a descendant"];
  / Both comparisons return 1b under a naive string-prefix test.
  if[decide[t;`read;`data.tradesecret]; '"`data.trades covered `data.tradesecret — string prefix, not segment prefix"];
  if[decide[t;`read;`data.instruments]; '"a grant covered a sibling"];
  }]

runTest[`parentGrantCoversDescendantsOnly; {[]
  .t.resetRbac[];
  grant[`readers;`read;`data];
  t:.t.subj[`readers];
  if[not decide[t;`read;`data];              '"a grant did not cover itself"];
  if[not decide[t;`read;`data.trades];       '"a parent grant did not cover a child"];
  if[not decide[t;`read;`data.trades.price]; '"a parent grant did not cover a grandchild"];
  / a sibling ROOT whose name merely starts with the granted string
  if[decide[t;`read;`datastore.x]; '"`data covered `datastore.x — string prefix, not segment prefix"];
  }]

runTest[`childGrantDoesNotCoverParent; {[]
  .t.resetRbac[];
  grant[`narrow;`read;`data.trades.price];
  t:.t.subj[`narrow];
  if[decide[t;`read;`data.trades]; '"cover ran upwards — a column grant conferred the table"];
  if[decide[t;`read;`data];        '"cover ran upwards to the root"];
  }]

/ decide's cover test is ancestor membership (`any (ancestorsOf r) in g`), not the per-grant `covers`
/ scan `holdersOf`/`explain` still use. The two must keep agreeing over the trap set that motivates
/ segment-wise cover in the first place, plus the shapes that only differ once cover is restated as
/ membership: a resource shorter than the grant, nulls mixed with real resources, and duplicates.
runTest[`decideAgreesWithCoversOverTheTrapSet; {[]
  .t.resetRbac[];
  grant[`g;`read;`data.trades];
  grant[`g;`read;`data];
  grant[`g;`read;`data.trades.price];
  t:.t.subj[`g];
  reference:{[gseg;r] any covers[;splitPath r] each gseg};
  gseg:splitPath each `data.trades`data`data.trades.price;
  / exact, both segment-boundary traps, exact again, a deeper match, deeper still, unrelated, null,
  / and a duplicate of the first — written as an explicit list to avoid any backtick-run ambiguity.
  cases:(`data.trades;`data.tradesecret;`datastore.x;`data;`data.trades.price;
    `data.trades.price.open;`ref;`;`data.trades);
  {[t;gseg;reference;r]
    want:reference[gseg;r];
    got:decide[t;`read;r];
    if[not want~got;
      '"decide disagreed with covers for ",(-3!r),": covers says ",(-3!want),", decide says ",-3!got]
    }[t;gseg;reference] each cases;
  }]

runTest[`decideIsFlatInPolicySize; {[]
  .t.resetRbac[];
  grant[`g;`read;`data.trades];
  small:decide[.t.subj[`g];`read;`data.trades.price];
  i:0;
  while[i<200; grant[`g;`read;`$"data.noise",string i]; i+:1];   / 203 applicable grants total
  big:decide[.t.subj[`g];`read;`data.trades.price];
  if[not small~big; '"decide's answer changed with policy size, at the same true grant"];
  }]

runTest[`resourceWildcardGrantStillCoversEverything; {[]
  .t.resetRbac[];
  grant[`g;`read;`];
  t:.t.subj[`g];
  if[not decide[t;`read;`data.trades]; '"a resource wildcard did not cover an ordinary resource"];
  if[not decide[t;`read;`];            '"a resource wildcard did not cover a null request resource"];
  .t.resetRbac[];
  grant[`g;`read;`data.trades];
  if[decide[.t.subj[`g];`read;`]; '"a null request resource was covered without a wildcard grant"];
  }]

/ ---- 2. no verb subsumption -----------------------------------------------------------------------
/ The verb axis is exact-match plus the wildcard, and nothing else. A deployment wanting write⊒read
/ writes two rows.
runTest[`noVerbSubsumption; {[]
  .t.resetRbac[];
  grant[`writers;`write;`data.trades];
  t:.t.subj[`writers];
  if[not decide[t;`write;`data.trades]; '"the granted verb was refused"];
  if[decide[t;`read;`data.trades];   '"`write conferred `read — the verb axis has no subsumption"];
  if[decide[t;`delete;`data.trades]; '"`write conferred `delete"];
  }]

/ ---- 3. the null wildcard -------------------------------------------------------------------------
runTest[`nullResourceIsAWildcard; {[]
  .t.resetRbac[];
  grant[`auditors;`read;`];
  t:.t.subj[`auditors];
  if[not decide[t;`read;`data.trades]; '"a null-resource grant did not cover a data resource"];
  if[not decide[t;`read;`kx.rbac];     '"a null-resource grant did not cover the control plane"];
  / still exact on the ACTION — a resource wildcard is not an action wildcard
  if[decide[t;`write;`data.trades]; '"a resource wildcard widened the action axis too"];
  }]

runTest[`nullActionIsAWildcard; {[]
  .t.resetRbac[];
  grant[`ops;`;`data.trades];
  t:.t.subj[`ops];
  if[not decide[t;`read;`data.trades];  '"a null-action grant did not cover `read"];
  if[not decide[t;`delete;`data.trades];'"a null-action grant did not cover `delete"];
  if[decide[t;`read;`kx.rbac]; '"an action wildcard widened the resource axis too"];
  }]

runTest[`bothNullIsTotal; {[]
  .t.resetRbac[];
  grant[`admins;`;`];
  t:.t.subj[`admins];
  if[not decide[t;`whatever;`any.thing.at.all]; '"the total wildcard did not cover an arbitrary pair"];
  }]

/ ---- 4. failure modes: deny, and never an error ---------------------------------------------------
/ A decision path that THROWS is not a denial. Each of these must return 0b.
runTest[`noSubjectDenies; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  if[decide[(::);`read;`data.trades];                          '"the unbound sentinel was allowed"];
  if[decide[()!();`read;`data.trades];                         '"an empty dict was allowed"];
  if[decide[(enlist `sub)!enlist `x;`read;`data.trades];       '"a principal with no `groups key was allowed"];
  if[decide[`sub`groups!(`x;`$());`read;`data.trades];         '"a principal with empty groups was allowed"];
  if[decide[`sub`groups!(`x;enlist `unknown);`read;`data.trades]; '"an unknown group was allowed"];
  }]

/ The unbound sentinel must deny without signalling.
runTest[`unboundSentinelDeniesRatherThanSignalling; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  r:.t.trap[{[] decide[(::);`read;`data.trades]}];
  if[not `ok ~ r; '"deciding on (::) signalled instead of denying: ", -3!r];
  if[decide[(::);`read;`data.trades]; '"the unbound sentinel was allowed"];
  }]

runTest[`emptyGrantSetDeniesEverything; {[]
  .t.resetRbac[];
  t:.t.subj[`traders];
  if[decide[t;`read;`data.trades]; '"an empty grant set allowed something"];
  }]

/ Grants do not affect kx.auth until its policy function is installed explicitly.
runTest[`policyFunctionIsNotInForceUntilSet; {[]
  .t.resetRbac[];
  setPolicy[{[p;a;r] 0b}];
  grant[`traders;`read;`data.trades];
  if[.t.rbacPolicyActive[]; '"the RBAC policy was active before setPolicy"];
  setLoginGroups[(enlist .t.u)!enlist `traders];
  .t.mustDeny[{[] authorize[`read;`data.trades]}];
  .t.installRbac[];
  if[not .t.rbacPolicyActive[]; '"setPolicy did not install the RBAC policy"];
  if[not `traders in (authorize[`read;`data.trades])`groups; '"RBAC did not decide after setPolicy"];
  }]

/ ---- 5. entitled: scalar policy over a resource vector -------------------------------------------
runTest[`entitledReturnsTheCoveredSubset; {[]
  .t.resetRbac[];
  .t.resetLogins[];
  grant[`traders;`read;`data.trades];
  grant[`traders;`read;`ref];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `traders];
  got:entitled[`read;`data.trades`data.tradesecret`ref.venues`data.instruments];
  if[not `data.trades`ref.venues ~ got; '"the entitled subset was wrong: ", -3!got];
  }]

runTest[`entitledPreservesTypeOnEmptyResult; {[]
  .t.resetRbac[];
  .t.resetLogins[];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `nobody];
  got:entitled[`read;`data.trades`other];
  if[not 11h = type got; '"an empty subset lost its symbol type — got ", -3!type got];
  if[count got; '"a subject with no grants was entitled to something"];
  }]

/ The vector verb applies the same scalar policy as authorize.
runTest[`entitledAgreesWithAuthorizePerResource; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data];
  grant[`traders;`read;`ref.venues];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `traders];
  rs:`data.trades`data.tradesecret`ref.venues`ref.other`kx.rbac;
  batch:entitled[`read; rs];
  / @[] directly rather than .t.trap: `.t.trap[f[x]]` would evaluate f[x] EAGERLY at the call site — a
  / fully-applied projection is not a deferred one — so the signal would escape before the trap saw it.
  oneByOne:rs where {[r] @[{[r] authorize[`read;r]; 1b}; r; {[e] 0b}]} each rs;
  if[not batch ~ oneByOne;
    '"entitled disagreed with per-resource authorize: ",(-3!batch)," vs ",-3!oneByOne];
  }]

/ policySpec[] is now the rank-4 decideMany, which answers a whole resource vector in one pass rather
/ than kx.auth's liftScalar calling `decide` once per resource. Pin decideMany's own output against the
/ per-resource `decide` loop directly, over the same trap set the cover-equivalence test uses — the
/ covered subset is recoverable from the `resources` obligation when one is present, or is the whole
/ request when it isn't (an unnarrowed request carries no obligations at all).
runTest[`batchDecisionAgreesWithPerResourceDecide; {[]
  .t.resetRbac[];
  grant[`g;`read;`data.trades];
  grant[`g;`read;`data];
  grant[`g;`read;`data.trades.price];
  t:.t.subj[`g];
  rs:(`data.trades;`data.tradesecret;`datastore.x;`data;`data.trades.price;
    `data.trades.price.open;`ref;`;`data.trades);
  d:decideMany[t;`read;rs;emptyCtx];
  oneByOne:decide[t;`read;] each rs;
  covered:$[`resources in key d`obligations; d[`obligations]`resources; rs];
  reference:rs where oneByOne;
  if[not covered~reference;
    '"decideMany's covered subset disagreed with per-resource decide: ",(-3!covered)," vs ",-3!reference];
  if[not (d`allowed)~any oneByOne;
    '"decideMany's `allowed disagreed with any per-resource decide"];
  }]

/ decideMany must build the SAME no-obligation flavour kx.auth's own liftScalar produces for a fully
/ satisfied plural request, or the two engines would answer structurally differently for identical
/ inputs. Compared structurally against liftScalar itself (both root names, since the suite loads both
/ modules flat) rather than against a restated literal, so the two can't silently drift apart.
runTest[`rankFourEngineAnswersNoObligationOnAnUnnarrowedRequest; {[]
  .t.resetRbac[];
  grant[`g;`read;`data];
  t:.t.subj[`g];
  rs:`data.trades`data.a;
  / liftScalar reads kx.auth's installed `policy` slot, so it needs the SCALAR decide installed to be
  / the fair comparison — decideMany itself is called directly below, not through the seam.
  setPolicy[decide];
  d:decideMany[t;`read;rs;emptyCtx];
  ref:liftScalar[t;`read;rs;emptyCtx];
  if[not d~ref;
    '"decideMany's no-obligation answer differs from kx.auth's liftScalar: ",(-3!d)," vs ",-3!ref];
  }]

runTest[`setPolicyRejectsNonFunctionsAtomically; {[]
  old:policy;
  .t.mustSignal[{[] setPolicy (enlist `authorize)!enlist decide}; "expects a function"];
  if[not old~policy; '"a rejected policy changed the active policy"];
  }]

/ ---- 6. mutation ----------------------------------------------------------------------------------
runTest[`grantIsIdempotent; {[]
  .t.resetRbac[];
  n:grant[`traders;`read;`data.trades];
  if[not 1=n; '"the first grant did not yield one row"];
  if[not 1=grant[`traders;`read;`data.trades]; '"re-granting the same row added a duplicate"];
  }]

runTest[`revokeRemovesOnlyTheExactRow; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data];
  grant[`traders;`read;`data.trades];
  revoke[`traders;`read;`data];
  t:.t.subj[`traders];
  if[not decide[t;`read;`data.trades]; '"revoking a parent removed a separately-granted child"];
  if[decide[t;`read;`data.instruments]; '"revoking the parent left its cover in place"];
  }]

runTest[`mutationBumpsTheVersion; {[]
  .t.resetRbac[];
  v0:policyVersion;
  grant[`traders;`read;`data.trades];
  if[not policyVersion > v0; '"grant did not bump the version counter"];
  v1:policyVersion;
  revoke[`traders;`read;`data.trades];
  if[not policyVersion > v1; '"revoke did not bump the version counter"];
  }]

runTest[`grantRejectsMalformedInput; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] grant[`traders;`read;`data..trades]}; "malformed resource path"];
  .t.mustSignal[{[] grant[`traders;`read;`.data]}; "malformed resource path"];
  .t.mustSignal[{[] grant[`traders;`read;`data.]}; "malformed resource path"];
  .t.mustSignal[{[] grant[`traders;`read;"data.trades"]}; "must be symbol atoms"];
  .t.mustSignal[{[] grant[`traders`viewers;`read;`data.trades]}; "must be symbol atoms"];
  .t.mustSignal[{[] grant[`;`read;`data.trades]}; "group must not be null"];
  .t.mustSignal[{[] revoke[`traders`viewers;`read;`data.trades]}; "must be symbol atoms"];
  }]

/ validateRow's symbol-atom check is exercised above only via grp (a vector) and res (a string) —
/ never via act. `all -11h = type each (g;a;r)` covers all three at once, but nothing had proven it.
runTest[`validateRowRejectsANonSymbolActionDirectly; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] grant[`traders;42;`data.trades]}; "must be symbol atoms"];
  .t.mustSignal[{[] revoke[`traders;42;`data.trades]}; "must be symbol atoms"];
  }]

/ ---- 7. the pre-split invariant ------------------------------------------------------------------
/ Paths are split at MUTATION time so a decision never calls string/vs on a grant. If a mutation path
/ ever forgets to populate `seg`, cover silently stops working — so assert it structurally.
/ NB the setGrants payload carries the control plane. Once a policy is viable, a replacement that would
/ drop the last `assert or `admin holder is refused — see § 16 — so a bare replacement here would fail on
/ the lockout guard rather than on anything about pre-splitting.
runTest[`everyStoredGrantIsPresplit; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  grant[`admins;`;`];
  setGrants[([] grp:`viewers`superUsers`policyAdmins;
                    act:`query`assert`admin;
                    res:`kdbx.sql`kx.identity`kx.rbac)];
  grant[`traders;`read;`ref.venues];
  bad:select from grantStore where not seg ~' splitPath each res;
  if[count bad; '"a stored grant's seg did not match its res: ", -3!bad];
  }]

/ ---- 8. structural validation --------------------------------------------------------------------
/ Validation covers STRUCTURE only, never the verb vocabulary — verbs are deployment-defined.
runTest[`setGrantsValidatesStructure; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] setGrants[([] grp:enlist `a; act:enlist `read)]}; "missing column"];
  .t.mustSignal[{[] setGrants[([] grp:enlist `a; act:enlist `read; res:enlist `data; deny:enlist 1b)]}; "unexpected column"];
  .t.mustSignal[{[] setGrants[([] grp:enlist `a; act:enlist `read; res:enlist "str")]}; "must be symbol"];
  .t.mustSignal[{[] setGrants[([] grp:enlist `; act:enlist `read; res:enlist `data)]}; "group must not be null"];
  .t.mustSignal[{[] setGrants[([] grp:enlist `a; act:enlist `read; res:enlist `data..x)]}; "malformed resource path"];
  .t.mustSignal[{[] setGrants[([] grp:`a`a; act:`read`read; res:`data.x`data.x)]}; "duplicate grant row"];
  .t.mustSignal[{[] setGrants[(enlist `notATable)]}; "expected a table"];
  }]

/ The three validation spots above are each proven with exactly one problem at a time. Two of them
/ ACCUMULATE simultaneous problems into one message; guardVital's per-vital-grant loop does the
/ opposite — it signals on the first vital pair only, so dropping both `assert` and `admin` at once
/ still reports just one. Nothing had constructed simultaneous multi-problem input to show either half.
runTest[`simultaneousMultiProblemInputAccumulatesOrShortCircuitsByDesign; {[]
  / (a) validate/validateGrantRows: a null group AND a malformed path at once, both reported.
  .t.resetRbac[];
  e:.t.trap[{[] setGrants[([] grp:enlist `; act:enlist `read; res:enlist `data..x)]}];
  if[not (count e ss "group must not be null") and count e ss "malformed resource path";
    '"expected both problems to accumulate: ",e];
  / (b) validateOperations: an unknown op, a null group and a malformed path, all three at once.
  .t.resetRbac[];
  e:.t.trap[{[] applyPersisted[([] op:enlist `delete; grp:enlist `; act:enlist `read; res:enlist `data..x);1b]}];
  if[not (count e ss "unknown operation") and (count e ss "group must not be null") and count e ss "malformed resource path";
    '"expected all three problems to accumulate: ",e];
  / (c) guardVital: dropping BOTH vital grants at once still names only the first (`assert`), not
  / both. Built inline rather than via .t.makeViable — that fixture is defined later in this file, in
  / § 17, and this test needs to run here in § 8.
  .t.resetRbac[];
  setGrants[([] grp:`superUsers`policyAdmins`trader;
                     act:`assert`admin`read;
                     res:`kx.identity`kx.rbac`data.trades)];
  e:.t.trap[{[] setGrants[([] grp:enlist `trader; act:enlist `read; res:enlist `data.trades)]}];
  if[not count e ss "assert:kx.identity"; '"expected the assert pair to be the one reported: ",e];
  if[count e ss "admin:kx.rbac"; '"guardVital unexpectedly reported BOTH vital pairs at once: ",e];
  }]

runTest[`aDeploymentDefinedVerbIsAccepted; {[]
  .t.resetRbac[];
  setGrants[([] grp:enlist `etl; act:enlist `backfill; res:enlist `data.trades)];
  if[not decide[.t.subj[`etl];`backfill;`data.trades]; '"an invented verb was not honoured"];
  }]

/ A malformed candidate must leave the PREVIOUSLY INSTALLED SET in force — never a partial apply.
runTest[`failedLoadLeavesThePriorSetInForce; {[]
  .t.resetRbac[];
  setGrants[([] grp:enlist `traders; act:enlist `read; res:enlist `data.trades)];
  before:grantStore;
  .t.mustSignal[{[] setGrants[([] grp:`a`a; act:`read`read; res:`dup`dup)]}; "duplicate"];
  if[not before ~ grantStore; '"a failed setGrants modified the live grant table"];
  if[not decide[.t.subj[`traders];`read;`data.trades]; '"the prior grant stopped working after a failed load"];
  }]

/ ---- 9. the reserved control-plane root is ordinary to the engine ---------------------------------
/ `kx.* is reserved by CONVENTION and documented, not enforced — the module's own grants live there
/ (`assert on `kx.identity, `admin on `kx.rbac), so the engine must treat it like any other path.
runTest[`controlPlaneResourcesAreOrdinaryPaths; {[]
  .t.resetRbac[];
  grant[`superUsers;`assert;`kx.identity];
  grant[`policyAdmins;`admin;`kx.rbac];
  if[not decide[.t.subj[`superUsers];`assert;`kx.identity]; '"the assert grant did not decide"];
  if[not decide[.t.subj[`policyAdmins];`admin;`kx.rbac];    '"the admin grant did not decide"];
  / and cover applies there as everywhere: a grant on `kx does cover both
  .t.resetRbac[];
  grant[`root;`;`kx];
  if[not decide[.t.subj[`root];`assert;`kx.identity]; '"cover did not apply under the reserved root"];
  }]

/ ---- 10. the engine end to end through the real seam ---------------------------------------------
/ Bind's assert gate, a data grant and a scope-down are decided by one installed engine and grant table.
runTest[`oneEngineAnswersAssertCapabilityAndData; {[]
  .t.resetRbac[];
  setGrants[([] grp:(`superUsers;   `viewers;  `traders;      `traders);
                    act:(`assert;       `query;    `read;         `write);
                    res:(`kx.identity;  `kdbx.sql; `data.trades;  `data.trades))];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `superUsers];
  / the assert gate: the caller's LOGIN holds the grant, so bind is permitted
  bind[`sub`groups!(`alice; `viewers`traders)];
  / capability + data, both from the same table
  if[not `alice ~ (authorize[`query;`kdbx.sql])`sub;   '"the capability check failed for alice"];
  if[not `alice ~ (authorize[`read;`data.trades])`sub; '"the data gate failed for alice"];
  .t.mustDeny[{[] authorize[`delete;`data.trades]}];   / no verb implies another
  / and the scope-down agrees
  if[not (enlist `data.trades) ~ entitled[`read;`data.trades`data.instruments];
    '"entitled did not scope down to the granted resource"];
  }]

/ A principal whose groups hold nothing clears no gate — the default-deny floor, through the real seam.
runTest[`grouplessPrincipalClearsNothing; {[]
  .t.resetRbac[];
  setGrants[([] grp:enlist `superUsers; act:enlist `assert; res:enlist `kx.identity)];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `superUsers];
  bind[(enlist `sub)!enlist `carol];
  .t.mustDeny[{[] authorize[`read;`data.trades]}];
  if[count entitled[`read;`data.trades]; '"a groupless principal was entitled to something"];
  }]

/ The installed engine is rank-4 (decideMany), but the assert gate calls the rank-agnostic `allows`
/ helper with a SINGLE resource, never `scope`, so it can only ever see a fully-allowed or
/ fully-denied answer — never a partial obligation. Pin that it stays exactly as boolean as it was
/ under the old rank-3 `decide`, for both directions.
runTest[`rankFourEngineLeavesTheAssertGatesBoolean; {[]
  .t.resetRbac[];
  setGrants[([] grp:enlist `superUsers; act:enlist `assert; res:enlist `kx.identity)];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `superUsers];
  bind[`sub`groups!(`alice; `viewers)];              / the login holds `assert; must succeed cleanly
  if[not `alice ~ current[]`sub; '"bind did not succeed although the login held `assert"];
  setLoginGroups[(enlist .t.u)!enlist `viewers];      / the login holds nothing now; must refuse cleanly
  .t.mustDeny[{[] bind[`sub`groups!(`bob; `viewers)]}];
  }]

/ ---- 11. inspection: grants / effective -----------------------------------------------------------
runTest[`grantsSnapshotOmitsTheDerivedColumn; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  g:grants[];
  if[not `grp`act`res ~ cols g; '"the snapshot exposed the derived seg column: ", -3! cols g];
  if[not 1=count g; '"the snapshot lost a row"];
  }]

runTest[`effectiveReturnsOnlyTheSubjectsRows; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  grant[`viewers;`query;`kdbx.sql];
  e:effective[.t.subj[`traders]];
  if[not 1=count e; '"effective returned the wrong row count: ", -3!e];
  if[not `traders ~ first e`grp; '"effective returned another group's rows"];
  if[count effective[.t.subj[`nobody]]; '"effective invented rows for an ungranted group"];
  }]

/ ---- 12. check: the pure dry-run -----------------------------------------------------------------
/ No bound principal, no handle. This purity is why a q process with the module loaded is already a
/ policy service, so it must not start depending on require[].
runTest[`checkIsPureAndNeedsNoBoundPrincipal; {[]
  .t.resetRbac[];
  setPolicy[{[p;a;r] 0b}];
  grant[`traders;`read;`data.trades];
  if[not check[.t.subj[`traders];`read;`data.trades]; '"check did not decide without an installed policy"];
  if[check[.t.subj[`traders];`delete;`data.trades];   '"check allowed an ungranted verb"];
  if[check[.t.subj[`nobody];`read;`data.trades];      '"check allowed an ungranted group"];
  }]

/ A canonical principal may carry a scalar group.
runTest[`checkAcceptsScalarGroup; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  if[not check[`sub`groups!(`alice;`traders);`read;`data.trades];
    '"a scalar-groups principal was refused where a vector one is allowed"];
  }]

runTest[`checkDeniesRatherThanSignallingOnJunk; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  {[x] if[not `ok ~ @[{[y] check[y;`read;`data.trades]; `ok}; x; {[e] e}];
        '"check signalled instead of denying on: ", -3!x]} each ((::); ()!(); enlist `notADict; 42);
  }]

/ `explain` and `effective` share `check`'s exact junk-principal chokepoint (groupsOf, init.q:28), but
/ the case above only covers a malformed OUTER shape (missing `groups` entirely) — never a `groups`
/ key that is PRESENT but not symbol-typed, which is the field most likely to arrive wrong from an
/ external IdP. All three crash on that today.
/ .
/ "A decision path that THROWS is not a denial" — the property § 4 above and `public/CLAUDE.md` both
/ call load-bearing. A non-symbol `groups` must therefore DENY, exactly as a missing one does. That is
/ what this asserts (finding kx.rbac #3).
runTest[`checkEffectiveAndExplainDenyRatherThanCrashOnANonSymbolGroupsValue; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  junk:`sub`groups!(`t;1 2 3);
  if[check[junk;`read;`data.trades]; '"a non-symbol groups value was ALLOWED"];
  if[count effective[junk]; '"a non-symbol groups value returned grant rows"];
  if[(explain[junk;`read;`data.trades])`allowed; '"explain allowed a non-symbol groups value"];
  }]

/ ---- 13. explain: why, not just whether ----------------------------------------------------------
runTest[`explainNamesTheMatchingRow; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data];
  e:explain[.t.subj[`traders];`read;`data.trades];
  if[not e`allowed; '"explain disagreed with the decision"];
  if[not 1=count e`matched; '"explain did not report the matching row"];
  if[not "read:data.trades" ~ e`pair; '"explain's display pair is wrong: ", e`pair];
  if[not count (e`reason) ss "read:data"; '"explain's reason did not name the granting row: ", e`reason];
  }]

/ The four denial reasons, each naming the FIRST stage that eliminated everything — that is the
/ actionable one, and it is the difference between an agent re-scoping and an agent probing blindly.
runTest[`explainDistinguishesTheDenialReasons; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  grant[`traders;`write;`data.trades];

  noGroups:explain[(enlist `sub)!enlist `x;`read;`data.trades];
  if[noGroups`allowed; '"a groupless subject was explained as allowed"];
  if[not count (noGroups`reason) ss "no groups"; '"wrong reason for a groupless subject: ", noGroups`reason];

  noRows:explain[.t.subj[`strangers];`read;`data.trades];
  if[not count (noRows`reason) ss "no grants at all"; '"wrong reason for an ungranted group: ", noRows`reason];

  wrongVerb:explain[.t.subj[`traders];`delete;`data.trades];
  if[not count (wrongVerb`reason) ss "hold no delete grant"; '"wrong reason for an ungranted verb: ", wrongVerb`reason];
  if[not count (wrongVerb`reason) ss "read:data.trades"; '"the ungranted-verb reason did not list what they DO hold"];

  noCover:explain[.t.subj[`traders];`read;`data.secrets];
  if[not count (noCover`reason) ss "no grant covers read:data.secrets"; '"wrong reason for an uncovered resource: ", noCover`reason];
  }]

runTest[`explainAgreesWithTheDecision; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data];
  grant[`auditors;`read;`];
  cases:((`traders;`read;`data.trades); (`traders;`read;`datastore.x); (`traders;`write;`data.trades);
         (`auditors;`read;`anything.at.all); (`nobody;`read;`data));
  {[c]
    p:.t.subj[c 0];
    / q evaluates right to left, so parenthesize the dict lookup before comparison.
    / `e`allowed <> decide[...]` would compare the SYMBOL `allowed` to a boolean and 'type.
    said:(explain[p;c 1;c 2])`allowed;
    if[said <> decide[p;c 1;c 2];
      '"explain and decide disagreed for ", -3!c]} each cases;
  }]

/ ---- 14. persistence ------------------------------------------------------------------------------
/ NB `^` would be elementwise FILL over two char vectors and 'length on unequal lengths — not an
/ "or else". Pick the directory explicitly, and guarantee the trailing slash.
.t.tmpDir:{[] d:getenv`TMPDIR; d:$[count d; d; "/tmp"]; $[d like "*/"; d; d,"/"]};
.t.tmpPath:{[] `$":",.t.tmpDir[],"kxauth-rbac-test-",string .z.i};

runTest[`saveLoadRoundTrips; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  grant[`admins;`;`];
  grant[`viewers;`query;`kdbx.sql];
  before:grants[];
  path:.t.tmpPath[];
  configureStore path;
  saveTo[];
  grantStore::presplit ([] grp:`symbol$(); act:`symbol$(); res:`symbol$());
  if[count grants[]; '"the reset did not empty the grant set"];
  loadFrom[];
  if[not before ~ grants[]; '"the grant table did not survive a save/load round trip"];
  / and the derived column was rebuilt, not restored from the file
  bad:select from grantStore where not seg ~' splitPath each res;
  if[count bad; '"load did not re-derive the seg column"];
  if[not decide[.t.subj[`traders];`read;`data.trades]; '"a restored grant does not decide"];
  hdel path;
  }]

runTest[`persistenceRequiresLocalPathConfiguration; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] saveTo[]}; "no policy store configured"];
  .t.mustSignal[{[] loadFrom[]}; "no policy store configured"];
  }]

/ pathOf's documented string-path support: a plain string is prepended with `:` to make an hsym. Both
/ demos rely on this — one passes a literal, the other passes getenv output.
/ NB expected values are BUILT rather than written as `:... literals — a hyphenated path inside a
/ symbol literal parses as unary minus, so concatenation avoids a source-level hazard.
runTest[`pathOfAcceptsAPlainStringPath; {[]
  plain:"/tmp/kxauth-rbac-test";
  if[not (`$":",plain) ~ pathOf plain; '"a plain string path was not hsym'd correctly"];
  }]

/ ... but the prepend is UNCONDITIONAL, so a string that ALREADY starts with `:` — exactly what a
/ getenv-supplied hsym-shaped value looks like — is double-prepended into an unusable `::` path, with
/ no error. A path that is already in hsym form should survive unchanged, which is what this asserts
/ (finding kx.rbac #10).
runTest[`pathOfDoesNotDoublePrependAnAlreadyColonedString; {[]
  coloned:":/tmp/kxauth-rbac-test";
  if[not (`$coloned) ~ pathOf coloned;
    '"pathOf double-prepended a string that already carried its colon: ", -3! pathOf coloned];
  }]

runTest[`saveQuotesTheConfiguredPath; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  path:`$":",.t.tmpDir[],"kxauth rbac ' path ",string .z.i;
  configureStore path;
  saveTo[];
  if[() ~ key path; '"save did not create the configured path"];
  hdel path;
  }]

/ Temp-then-rename: nothing is left behind, so no half-written file can be mistaken for the real one.
runTest[`saveLeavesNoTempFile; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  path:.t.tmpPath[];
  configureStore path;
  saveTo[];
  if[not () ~ key `$(string path),".tmp"; '"save left its temp file behind"];
  hdel path;
  }]

runTest[`loadReplacesRatherThanMerges; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  path:.t.tmpPath[];
  configureStore path;
  saveTo[];
  grantStore::presplit ([] grp:`symbol$(); act:`symbol$(); res:`symbol$());
  grant[`others;`read;`data.other];             / a different baseline
  loadFrom[];
  if[count select from grants[] where grp=`others;
    '"load MERGED with the existing set instead of replacing it — silent precedence in a policy store"];
  if[not 1=count grants[]; '"load did not install exactly the saved set"];
  hdel path;
  }]

runTest[`loadOfAMissingFileSignals; {[]
  .t.resetRbac[];
  configureStore `$":/nonexistent/kxauth/grants";
  .t.mustSignal[{[] loadFrom[]}; "no such file"];
  }]

/ The `get`-fails branch of loadFrom was never exercised — only "no such file" was. This first used a
/ real `chmod 000`, verified live locally; it then failed in CI, because the pipeline runs as ROOT and
/ root reads a 000 file regardless. That is the same hazard transactionPersistenceFailureLeavesMemoryUntouched
/ documents, and the same lesson: make the boundary fail by construction, not by permissions.
/ The module does not branch on WHY the read failed — `@[get;p;…]` traps everything — so an unparseable
/ file exercises the identical branch and does it identically for root and for an ordinary user.
/ Distinct from loadOfAMalformedFileLeavesThePriorSetInForce, which writes a VALID q file of the wrong
/ SHAPE: that one gets past `get` and fails later in replaceGrants' validation, with "missing column".
runTest[`loadOfAnUnreadableFileSignalsDistinctly; {[]
  .t.resetRbac[];
  path:.t.tmpPath[];
  path 1: "not a serialised q object";     / `key` sees a file, so this reaches `get`, which cannot read it
  configureStore path;
  .t.mustSignal[{[] loadFrom[]}; "cannot read the file"];
  hdel path;
  }]

/ A malformed source must fail the load and leave the previously installed set IN FORCE.
runTest[`loadOfAMalformedFileLeavesThePriorSetInForce; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  before:grants[];
  path:.t.tmpPath[];
  path set ([] wrong:enlist `shape);                / not a grant table
  / .t.mustSignal needs a NILADIC lambda. `{[p] …}[path]` is FULLY APPLIED, so it evaluates here and the
  / signal escapes before the trap sees it — stash the argument instead.
  configureStore path;
  .t.mustSignal[{[] loadFrom[]}; "missing column"];
  if[not before ~ grants[]; '"a failed load modified the live grant table"];
  if[not decide[.t.subj[`traders];`read;`data.trades]; '"the prior grant stopped working after a failed load"];
  hdel path;
  }]

/ ---- 15. atomic policy transactions --------------------------------------------------------------
.t.ops:{[op;grp;act;res] ([] op:(),op; grp:(),grp; act:(),act; res:(),res)};
.t.transactionViable:{[] .t.resetRbac[]; setGrants ([] grp:`superUsers`policyAdmins`trader;
                                                       act:`assert`admin`read;
                                                       res:`kx.identity`kx.rbac`data.trades); };

/ apply/replace's dryRun boolean-type guard is the first statement in each, so it fires before
/ touching anything else — but every call site in the repo happens to pass a literal 0b/1b.
runTest[`dryRunMustBeABooleanAtom; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] applyPersisted[.t.ops[`grant;`traders;`read;`data.trades];1]}; "dryRun must be a boolean atom"];
  .t.mustSignal[{[] replacePersisted[([] grp:enlist `traders; act:enlist `read; res:enlist `data.trades);`yes]}; "dryRun must be a boolean atom"];
  }]

runTest[`transactionDryRunIsPureAndNeedsNoStore; {[]
  .t.resetRbac[];
  before:grants[];
  base:policyVersion;
  result:applyPersisted[.t.ops[`grant;`traders;`read;`data.trades];1b];
  if[not result`dryRun; '"the result did not identify a dry-run"];
  if[result`persisted; '"a dry-run claimed to persist"];
  if[result`wouldPersist; '"a dry-run with no configured store claimed it could persist"];
  if[not result`changed; '"the dry-run did not identify a policy change"];
  if[not 1=count result`added; '"the dry-run did not report its added row"];
  if[not before~grants[]; '"a dry-run modified the live grants"];
  if[not base=policyVersion; '"a dry-run bumped the live version"];
  }]

/ The test above only covers dryRun with NO store configured. The other half of wouldPersist/persisted's
/ contract — a store IS configured, so wouldPersist should flip to true, but persisted must still stay
/ false since a dry-run writes nothing — was never exercised.
runTest[`dryRunWithAConfiguredStoreReportsWouldPersistButDoesNotPersist; {[]
  .t.resetRbac[];
  path:.t.tmpPath[];
  configureStore path;
  result:applyPersisted[.t.ops[`grant;`traders;`read;`data.trades];1b];
  if[not result`wouldPersist; '"a dry-run with a configured store did not report wouldPersist"];
  if[result`persisted; '"a dry-run reported persisted even though nothing should be written"];
  if[not () ~ key path; '"a dry-run wrote to the configured store"];
  }]

runTest[`transactionPersistsThenInstallsExactlyOnce; {[]
  .t.transactionViable[];
  path:.t.tmpPath[];
  configureStore path;
  base:policyVersion;
  ops:(.t.ops[`grant;`viewers;`query;`kdbx.sql]),.t.ops[`revoke;`trader;`read;`data.trades];
  result:applyPersisted[ops;0b];
  if[not result`persisted; '"a committed transaction did not report persistence"];
  if[not base+1=policyVersion; '"a two-operation transaction bumped the version more than once"];
  if[not grants[]~get path; '"the persisted snapshot differs from the installed policy"];
  if[check[.t.subj[`trader];`read;`data.trades]; '"the revoked grant survived the transaction"];
  if[not check[.t.subj[`viewers];`query;`kdbx.sql]; '"the granted row did not take effect"];
  hdel path;
  }]

runTest[`transactionRequiresAStoreBeforeChangingMemory; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  before:grants[];
  base:policyVersion;
  .t.mustSignal[{[] applyPersisted[.t.ops[`grant;`viewers;`read;`data.other];0b]}; "no policy store configured"];
  if[not before~grants[]; '"a transaction without a store changed the live policy"];
  if[not base=policyVersion; '"a transaction without a store bumped the version"];
  }]

/ Persistence is the commit point: if the temp snapshot cannot be written, the live policy and version
/ must remain exactly as they were. Inject the boundary failure rather than guessing an unwritable path:
/ CI runs as root, so `/nonexistent` is writable there even though it fails for an ordinary local user.
runTest[`transactionPersistenceFailureLeavesMemoryUntouched; {[]
  .t.transactionViable[];
  before:grants[];
  base:policyVersion;
  realWrite:writeSnapshot;
  writeSnapshot::{[t] '"injected policy write failure"};
  e:.t.trap {[] applyPersisted[.t.ops[`grant;`viewers;`read;`data.other];0b]};
  writeSnapshot::realWrite;
  if[not 10h=type e; '"the injected persistence failure did not signal: ",-3!e];
  if[not count e ss "injected policy write failure"; '"the transaction signalled for the wrong reason: ",e];
  if[not before~grants[]; '"a failed policy write changed the live grants"];
  if[not base=policyVersion; '"a failed policy write bumped the version"];
  }]

/ ---- a directory is never a store -----------------------------------------------------------------
/ `mv` into an existing directory succeeds, so a directory store used to report persisted=1b while
/ load[] refused what it had written. Both ends refuse it now: configureStore up front, and the write
/ itself, because a directory can appear at the configured path later.
.t.tmpStoreDir:{[] `$":",.t.tmpDir[],"kxauth-rbac-dir-",string .z.i};

runTest[`configureStoreRefusesADirectory; {[]
  .t.resetRbac[];
  d:.t.tmpStoreDir[];
  system "mkdir -p ",1_string d;
  .t.mustSignal[{[] configureStore .t.tmpStoreDir[]}; "the store path is a directory"];
  if[not (::)~storePath; '"a refused configureStore still set the store path"];
  system "rmdir ",1_string d;
  }]

runTest[`writeRefusesAStorePathThatBecameADirectory; {[]
  .t.transactionViable[];
  d:.t.tmpStoreDir[];
  configureStore d;                                     / a file path when configured
  system "mkdir -p ",1_string d;                        / and a directory by the time of the write
  before:grants[];
  base:policyVersion;
  .t.mustSignal[{[] saveTo[]}; "the store path is a directory"];
  e:.t.trap {[] applyPersisted[.t.ops[`grant;`viewers;`read;`data.other];0b]};
  if[not 10h=type e; '"a persisted apply onto a directory did not signal: ",-3!e];
  if[not count e ss "the store path is a directory"; '"the apply signalled for the wrong reason: ",e];
  if[not before~grants[]; '"a refused write changed the live grants"];
  if[not base=policyVersion; '"a refused write bumped the version"];
  if[count key d; '"a refused write left a file inside the directory"];
  if[not ()~key `$(string d),".tmp"; '"a refused write left its temp file behind"];
  system "rmdir ",1_string d;
  }]

runTest[`absentRevokeIsAnAcknowledgedNoOp; {[]
  .t.transactionViable[];
  result:applyPersisted[.t.ops[`revoke;`viewer;`read;`data.missing];1b];
  if[result`changed; '"an absent revoke was reported as a change"];
  if[count result`removed; '"an absent revoke reported a removed row"];
  }]

runTest[`transactionValidatesAllOperationsBeforeChangingState; {[]
  .t.resetRbac[];
  before:grants[];
  .t.badOps::.t.ops[`delete;`viewers;`read;`data.other];
  .t.mustSignal[{[] applyPersisted[.t.badOps;1b]}; "unknown operation"];
  if[not before~grants[]; '"an invalid operation changed the live policy"];
  }]

runTest[`transactionGuardsTheFinalPolicyNotIntermediateRows; {[]
  .t.transactionViable[];
  path:.t.tmpPath[];
  configureStore path;
  ops:(.t.ops[`revoke;`policyAdmins;`admin;`kx.rbac]),.t.ops[`grant;`backupAdmins;`admin;`kx.rbac];
  applyPersisted[ops;0b];
  if[not (enlist `backupAdmins)~holdersOf[grantStore;`admin;`kx.rbac];
    '"the transaction did not hand administration to the replacement holder"];
  hdel path;
  }]

/ Operation rows are an ordered patch, not a grant snapshot: repeating the same tuple is meaningful,
/ idempotent, and safe to retry after an uncertain client response.
runTest[`transactionOperationsAreOrderedAndRetrySafe; {[]
  .t.transactionViable[];
  path:.t.tmpPath[];
  configureStore path;
  same:.t.ops[`grant;`viewer;`read;`data.other];
  result:applyPersisted[same,same;0b];
  if[not result`changed; '"the first repeated grant batch did not change the policy"];
  if[1<>count select from grants[] where grp=`viewer,act=`read,res=`data.other;
    '"repeated grants created duplicate rows"];
  retry:applyPersisted[same,same;0b];
  if[retry`changed; '"retrying the same idempotent batch reported a change"];
  revokeGrant:(.t.ops[`revoke;`policyAdmins;`admin;`kx.rbac]),
              .t.ops[`grant;`policyAdmins;`admin;`kx.rbac];
  applyPersisted[revokeGrant;0b];
  if[not anyoneHolds[grantStore;`admin;`kx.rbac];
    '"revoke then grant did not preserve the final vital grant"];
  grantRevoke:(.t.ops[`grant;`viewer;`write;`data.other]),
              .t.ops[`revoke;`viewer;`write;`data.other];
  applyPersisted[grantRevoke;0b];
  if[count select from grants[] where grp=`viewer,act=`write,res=`data.other;
    '"grant then revoke did not leave the row absent"];
  hdel path;
  }]

/ A retry loop that has already applied everything sends an empty batch. It must commit as a no-op
/ rather than fail, and both transports must agree — the Envoy demo's gateway route builds the same
/ empty table from JSON, where untyped columns would be rejected as non-symbol input.
runTest[`anEmptyOperationBatchCommitsAsANoOp; {[]
  .t.transactionViable[];
  path:.t.tmpPath[];
  configureStore path;
  before:grants[];
  result:applyPersisted[.t.ops[`symbol$();`symbol$();`symbol$();`symbol$()];0b];
  if[result`changed; '"an empty operation batch reported a change"];
  if[not before~grants[]; '"an empty operation batch altered the live policy"];
  if[count result`added; '"an empty operation batch reported added rows"];
  if[count result`removed; '"an empty operation batch reported removed rows"];
  hdel path;
  }]

/ A transaction derives its candidate once and hands the same value to the guard, the lint, the store
/ and the live table. Pin that those four agree — a future change that re-derived any one of them
/ separately could let the persisted policy and the installed policy disagree after a clean commit.
runTest[`aCommittedTransactionInstallsExactlyWhatItPersisted; {[]
  .t.transactionViable[];
  path:.t.tmpPath[];
  configureStore path;
  ops:(.t.ops[`grant;`viewer;`read;`data.trades.price]),.t.ops[`grant;`viewer;`;`ref.venues];
  result:applyPersisted[ops;0b];
  if[not result`persisted; '"the transaction reported that it did not persist"];
  persisted:get path;
  installed:`grp`act`res#grantStore;
  if[not persisted~installed;
    '"the persisted table and the installed table differ: ", (-3!persisted), " vs ", -3!installed];
  if[(count persisted)<>result`afterCount;
    '"the reported afterCount does not match what was persisted"];
  / The store holds the BARE grant; the derived segments belong only to the in-memory table.
  if[`seg in cols persisted; '"the persisted snapshot leaked the derived seg column"];
  if[count select from grantStore where not seg ~' splitPath each res;
    '"a committed grant's seg did not match its res"];
  hdel path;
  }]

runTest[`replacementDryRunLintsTheCandidate; {[]
  .t.resetRbac[];
  candidate:([] grp:enlist `traders; act:enlist `read; res:enlist `data.trades);
  result:replacePersisted[candidate;1b];
  if[not 2=count result`findings;
    '"candidate verification did not report its missing control-plane grants: ",-3!result`findings];
  if[count grants[]; '"a replacement dry-run installed its candidate"];
  }]

runTest[`replacementCommitPersistsTheWholeSnapshot; {[]
  .t.resetRbac[];
  path:.t.tmpPath[];
  configureStore path;
  candidate:([] grp:`superUsers`policyAdmins`trader;
                act:`assert`admin`read;
                res:`kx.identity`kx.rbac`data.trades);
  result:replacePersisted[candidate;0b];
  if[not result`persisted; '"the replacement did not report persistence"];
  if[not candidate~grants[]; '"the replacement did not install the requested snapshot"];
  if[not candidate~get path; '"the replacement did not persist the requested snapshot"];
  hdel path;
  }]

/ replacePersisted has its OWN `validate t` call (init.q:349) — a distinct code path from setGrants's
/ (via replaceGrants). Every existing replacePersisted test hands it a well-formed table, so this
/ call has only ever been proven through setGrants's copy of the same check.
runTest[`replacePersistedRejectsAMalformedTableBeforeTouchingTheStore; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  before:grants[];
  .t.mustSignal[{[] replacePersisted[([] grp:enlist `a; act:enlist `read);0b]}; "invalid grant table"];
  if[not before ~ grants[]; '"a rejected replace touched the live grant table"];
  }]

/ ---- 16. mutations authorize through the same engine ---------------------------------------------
/ Self-governing: the gate is authorize[`admin;`kx.rbac], the engine's own decision, not a new seam.
/ In-process .z.w is 0, which IS the documented local-bypass path — so the remote half is covered by the
/ demo client, and what this pins is that the bypass exists and is what the tests have been relying on.
runTest[`localCallerBypassesTheAdminGate; {[]
  .t.resetRbac[];
  .t.installRbac[];                                    / engine in force, and NOBODY holds admin:kx.rbac
  if[not 0=.z.w; '"precondition failed: this check assumes an in-process caller"];
  n:grant[`traders;`read;`data.trades];         / must succeed anyway — the bootstrap path
  if[not 1=n; '"a local mutation was refused, so no first grant could ever be made"];
  revoke[`traders;`read;`data.trades];
  }]

/ The gate itself: with the engine installed and the admin grant absent, the decision it delegates to
/ must refuse; with the grant present, allow. requireAdmin reads .z.w, so drive the decision rather
/ than fake a handle.
runTest[`adminGateConsultsTheEngineItGoverns; {[]
  .t.resetRbac[];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `policyAdmins];
  if[check[.t.subj[`policyAdmins];`admin;`kx.rbac];
    '"admin:kx.rbac was allowed with no such grant in the table"];
  grant[`policyAdmins;`admin;`kx.rbac];
  if[not check[.t.subj[`policyAdmins];`admin;`kx.rbac];
    '"the admin grant did not take effect through the engine's own decision"];
  / and it is an ordinary grant, so it is subject to the ordinary rules
  if[check[.t.subj[`policyAdmins];`admin;`kx.other]; '"the admin grant covered an unrelated resource"];
  if[check[.t.subj[`otherFolk];`admin;`kx.rbac];     '"the admin grant applied to another group"];
  }]

/ ---- 17. the lockout guard: you may not throw the keys into the locked room ----------------------
/ Two grants cannot be restored remotely once gone: `assert on `kx.identity (without it no user session
/ can be established) and `admin on `kx.rbac (without it no remote caller can repair anything). Losing
/ either is not a degraded policy, it is a bricked process whose only repair is console access — and in a
/ container there may be no console. So every path that can REMOVE a grant refuses that transition.
/ .
/ The guard is MONOTONE: it refuses to take the LAST holder away, and never blocks a policy that simply
/ has not got there yet. That distinction is what keeps bootstrapping working.
.t.viableGrants:{[] ([] grp:`superUsers`policyAdmins`trader;
                        act:`assert`admin`read;
                        res:`kx.identity`kx.rbac`data.trades)};
.t.makeViable:{[] .t.resetRbac[]; setGrants .t.viableGrants[]; };

runTest[`revokingTheLastAssertGrantIsRefused; {[]
  .t.makeViable[];
  .t.mustSignal[{[] revoke[`superUsers;`assert;`kx.identity]}; "REFUSED: no group would be left able to"];
  if[not anyoneHolds[grantStore;`assert;`kx.identity]; '"the assert grant was removed anyway"];
  }]

runTest[`revokingTheLastAdminGrantIsRefused; {[]
  .t.makeViable[];
  .t.mustSignal[{[] revoke[`policyAdmins;`admin;`kx.rbac]}; "REFUSED: no group would be left able to"];
  if[not anyoneHolds[grantStore;`admin;`kx.rbac]; '"the admin grant was removed anyway"];
  }]

/ The error has to be worth reading: what breaks, who holds it now, and what to do instead.
runTest[`theLockoutErrorIsActuallyUseful; {[]
  .t.makeViable[];
  e:.t.trap[{[] revoke[`policyAdmins;`admin;`kx.rbac]}];
  / q truncates a signalled string at 254 chars, so everything a REMOTE caller needs must fit — a
  / remote caller never sees the fuller detail the guard also prints locally.
  / NB the comparison must be `&lt;=`, not `&lt;`. The truncation has ALREADY happened by the time the
  / signal is caught, so `count e` can never exceed 254 and `254 &lt; count e` could never fire — the
  / assertion was unfalsifiable (finding kx.rbac #5). Hitting exactly 254 IS the
  / evidence that something was clipped; today's real signal is 215.
  if[254 <= count e; '"the lockout signal hit q's 254-char limit, so a remote caller saw a truncated message"];
  {[e;what] if[not count e ss what; '"the lockout error does not mention \"",what,"\": ",e]}[e] each
    ("admin:kx.rbac"; "policyAdmins"; "console access"; "same call");
  }]

/ theLockoutErrorIsActuallyUseful above only ever has 1 holder, so the "3<count was" truncation
/ (init.q:68) — the "+N more" form — has never actually fired; every lockout test uses 1-2 holders.
runTest[`guardVitalTruncatesFourOrMoreHolders; {[]
  .t.resetRbac[];
  setGrants[([] grp:`g1`g2`g3`g4`g5; act:5#enlist `assert; res:5#enlist `kx.identity)];
  e:.t.trap[{[] setGrants[([] grp:enlist `nobody; act:enlist `read; res:enlist `data.x)]}];
  if[not count e ss "g1 g2 g3 +2 more"; '"expected the truncated 4+-holder display, got: ",e];
  if[count e ss "g4"; '"the truncated display leaked a 4th name into the remote signal: ",e];
  / `&lt;=` for the same reason as theLockoutErrorIsActuallyUseful above — see the note there.
  if[254 <= count e; '"the truncated lockout signal still hit q's 254-char limit"];
  }]

/ Revoking a NON-last holder is fine — the guard is about viability, not about protecting rows.
runTest[`revokingARedundantControlPlaneGrantIsAllowed; {[]
  .t.makeViable[];
  grant[`backupAdmins;`admin;`kx.rbac];
  revoke[`policyAdmins;`admin;`kx.rbac];        / another holder remains, so this is permitted
  if[not (enlist `backupAdmins) ~ holdersOf[grantStore;`admin;`kx.rbac];
    '"the remaining admin holder is wrong: ", -3! holdersOf[grantStore;`admin;`kx.rbac]];
  }]

/ The bare revoke[]/setGrants[] guard tests above never drove a lockout THROUGH the transaction verbs —
/ applyPersisted and replacePersisted must refuse one just as directly.
runTest[`applyPersistedRefusesALockoutCausingTransaction; {[]
  .t.makeViable[];
  .t.mustSignal[{[] applyPersisted[.t.ops[`revoke;`superUsers;`assert;`kx.identity];0b]};
    "REFUSED: no group would be left able to"];
  if[not anyoneHolds[grantStore;`assert;`kx.identity]; '"the assert grant was removed anyway"];
  }]

runTest[`replacePersistedRefusesALockoutCausingTransaction; {[]
  .t.makeViable[];
  / .t.mustSignal needs a NILADIC lambda; a local here would not be visible once passed through
  / trap/invoked, per the same trap loadOfAMalformedFileLeavesThePriorSetInForce documents — stash it.
  .t.candidateWithoutAssert:([] grp:enlist `policyAdmins; act:enlist `admin; res:enlist `kx.rbac);
  .t.mustSignal[{[] replacePersisted[.t.candidateWithoutAssert;0b]};
    "REFUSED: no group would be left able to"];
  if[not anyoneHolds[grantStore;`assert;`kx.identity]; '"the assert grant was removed anyway"];
  }]

/ replacementCommitPersistsTheWholeSnapshot (earlier in this file) only ever starts from an EMPTY grant
/ table, so replace and merge look identical there — nothing to drop. Prove the drop actually happens
/ against a NON-empty prior policy: in memory, in the persisted file, and in what a live decision
/ actually returns. Needs .t.makeViable, defined just above, so it can't live any earlier in the file.
runTest[`replacePersistedRemovesGrantsNotInTheNewSnapshot; {[]
  .t.makeViable[];
  path:.t.tmpPath[];
  configureStore path;
  candidate:([] grp:`superUsers`policyAdmins; act:`assert`admin; res:`kx.identity`kx.rbac);
  result:replacePersisted[candidate;0b];
  if[not result`persisted; '"the replacement did not report persistence"];
  if[not candidate~grants[]; '"a prior grant not in the candidate survived the replace"];
  if[not candidate~get path; '"the persisted file still carries the dropped grant"];
  if[check[.t.subj[`trader];`read;`data.trades]; '"the dropped grant still decides as allowed"];
  hdel path;
  }]

/ setGrants and load replace the full policy, including its control-plane grants.
runTest[`replacingAwayTheControlPlaneIsRefused; {[]
  .t.makeViable[];
  before:grants[];
  .t.mustSignal[{[] setGrants[([] grp:`trader`viewer; act:`read`query; res:`data.trades`kdbx.sql)]}; "REFUSED: no group would be left able to"];
  if[not before ~ grants[]; '"a refused replacement modified the live policy"];
  }]

runTest[`replacingWithTheControlPlaneIncludedIsAllowed; {[]
  .t.makeViable[];
  setGrants[([] grp:`superUsers`policyAdmins`viewer;
                    act:`assert`admin`query;
                    res:`kx.identity`kx.rbac`kdbx.sql)];
  if[not 3=count grants[]; '"the replacement did not land"];
  if[check[.t.subj[`trader];`read;`data.trades]; '"the old data grant survived a replacement"];
  }]

/ setGrants must never write through to a configured store — it's the in-memory-only replace verb,
/ contrasted with apply/replace which persist. Confirmed by absence, not just by reading the code:
/ the file must simply not exist after the call.
runTest[`setGrantsDoesNotPersistEvenWithAStoreConfigured; {[]
  .t.resetRbac[];
  path:.t.tmpPath[];
  configureStore path;
  setGrants[([] grp:enlist `traders; act:enlist `read; res:enlist `data.trades)];
  if[not () ~ key path; '"setGrants wrote to the configured store; it must stay in-memory only"];
  }]

/ A load of a snapshot that predates the control plane is the same hazard by another route.
runTest[`loadingASnapshotWithoutTheControlPlaneIsRefused; {[]
  .t.resetRbac[];
  grant[`trader;`read;`data.trades];             / not yet viable, so saving this is allowed
  path:.t.tmpPath[];
  configureStore path;
  saveTo[];
  .t.makeViable[];                                   / now the live policy IS viable
  configureStore path;
  .t.mustSignal[{[] loadFrom[]}; "REFUSED: no group would be left able to"];
  if[not anyoneHolds[grantStore;`admin;`kx.rbac]; '"a refused load removed the control plane"];
  hdel path;
  }]

/ ---- 18. ... and bootstrapping still works ------------------------------------------------------
/ The guard must never block a policy being BUILT. A host script's first grant[] call necessarily leaves
/ the policy without one of the two vital grants, so a naive "the result must be viable" rule would make
/ the module impossible to configure. This is the check that keeps that from regressing.
runTest[`bootstrappingFromAnEmptyPolicyIsNotBlocked; {[]
  .t.resetRbac[];
  / declared one at a time, in the order a host script would write them
  grant[`superUsers;`assert;`kx.identity];       / viable for assert, NOT for admin
  grant[`policyAdmins;`admin;`kx.rbac];
  grant[`trader;`read;`data.trades];
  if[not 3=count grants[]; '"a bootstrap sequence was blocked"];
  }]

/ ... including the other order, and including a bulk first install.
runTest[`bootstrappingInAnyOrderIsNotBlocked; {[]
  .t.resetRbac[];
  grant[`policyAdmins;`admin;`kx.rbac];          / admin first this time
  grant[`superUsers;`assert;`kx.identity];
  if[not 2=count grants[]; '"the reverse bootstrap order was blocked"];
  .t.resetRbac[];
  setGrants[([] grp:enlist `trader; act:enlist `read; res:enlist `data.trades)];
  if[not 1=count grants[]; '"a bulk install into an empty policy was blocked"];
  }]

/ An already-broken policy can still be repaired — the guard must not cement a bad state in place.
runTest[`aPolicyThatLostItsControlPlaneCanStillBeRepaired; {[]
  .t.resetRbac[];
  grant[`trader;`read;`data.trades];             / never viable
  revoke[`trader;`read;`data.trades];            / and freely mutable
  grant[`superUsers;`assert;`kx.identity];
  if[not 1=count grants[]; '"repair of a non-viable policy was blocked"];
  }]

/ ---- 18. verify[] — the maintenance lint --------------------------------------------------------
runTest[`verifyFlagsAnUnusablePolicy; {[]
  .t.resetRbac[];
  v:verify[];
  issues:v`issue;
  if[not any issues like "*no group can assert*"; '"verify did not flag the missing assert grant: ", -3!issues];
  if[not any issues like "*no group can administer*"; '"verify did not flag the missing admin grant"];
  if[not `error in v`severity; '"a policy nobody can use was not an ERROR"];
  }]

runTest[`verifyIsQuietOnAHealthyPolicy; {[]
  .t.makeViable[];
  v:verify[];
  if[count v; '"verify complained about a healthy policy: ", -3!v];
  }]

runTest[`verifyAcceptsATierThatCanBothAssertAndAdminister; {[]
  .t.resetRbac[];
  grant[`omni;`assert;`kx.identity];
  grant[`omni;`admin;`kx.rbac];
  if[count verify[]; '"verify rejected a valid shared control-plane tier"];
  }]

/ The subject rule means an unbound handle decides as the connecting login, so an asserter tier holding
/ data grants turns a missing bind into a silent read rather than a denial.
runTest[`verifyFlagsAnAsserterTierHoldingDataGrants; {[]
  .t.resetRbac[];
  grant[`svc;`assert;`kx.identity];
  grant[`svc;`read;`data.trades];
  grant[`policyAdmins;`admin;`kx.rbac];
  if[not any (verify[]`issue) like "*asserter tier also holds non-control-plane*";
    '"verify did not flag an asserter tier with data grants: ", -3! verify[]`issue];
  }]

/ The leak detector's `first each seg` reduction (init.q:293) treats a wildcard resource's empty
/ split identically to a real path — an untested edge of the same mechanism above, this time with a
/ wildcard-resource grant rather than a concrete one.
runTest[`verifyFlagsAnAsserterTierHoldingAWildcardGrant; {[]
  .t.resetRbac[];
  grant[`svc;`assert;`kx.identity];
  grant[`svc;`read;`];
  grant[`policyAdmins;`admin;`kx.rbac];
  if[not any (verify[]`issue) like "*asserter tier also holds non-control-plane*";
    '"verify did not flag an asserter tier with a wildcard-resource grant: ", -3! verify[]`issue];
  }]

runTest[`verifyNotesATotalWildcard; {[]
  .t.makeViable[];
  grant[`admins;`;`];
  if[not any (verify[]`issue) like "*total wildcard*"; '"verify did not note a total wildcard"];
  }]

/ CI wants a build failure, not a printout.
runTest[`verifyOrDieSignalsOnAnError; {[]
  .t.resetRbac[];
  .t.mustSignal[{[] report[1b]}; "policy is unusable"];
  .t.makeViable[];
  if[count report[1b]; '"a healthy policy was reported as having issues"];
  }]

/ report[fatal=0b] is never called anywhere else in the suite — only report[1b] is. Corrects a now-fixed
/ factual error in the older cross-reference section, which had wrongly claimed fatal=0b was COVERED
/ by the test above (it isn't — that test only ever passes 1b).
runTest[`reportFatalFalseReturnsFindingsWithoutSignalling; {[]
  .t.resetRbac[];
  v:.t.trap[{[] report[0b]}];
  if[not `ok~v; '"report[0b] signalled on an unusable policy, but fatal was false: ",-3!v];
  v:report[0b];
  if[not `error in v`severity; '"report[0b] on an unusable policy lost the error-severity finding"];
  }]

/ ---- 19. the unset-policy diagnostic -------------------------------------------------------------
/ "denied: alice not permitted read on data.trades" is indistinguishable from a real denial when the true
/ cause is that nobody called setPolicy[].
runTest[`anUninstalledPolicyExplainsItselfOnDenial; {[]
  .t.resetRbac[];
  / Through setPolicy, not `policy::`, so `policyRank` tracks it — the hint keys on `policy~denyAll`, which
  / installing the default satisfies exactly as never having installed one does.
  setPolicy[denyAll];
  e:.t.trap[{[] authorize[`read;`data.trades]}];
  if[not count e ss "no authorization policy is installed"; '"a denial from the default policy did not say so: ",e];
  if[not count e ss "setPolicy"; '"the diagnostic did not name the fix"];
  }]

/ ... and a REAL denial must not carry the hint, or it becomes noise nobody reads.
runTest[`aRealDenialDoesNotCarryTheHint; {[]
  .t.makeViable[];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `trader];
  e:.t.trap[{[] authorize[`delete;`data.trades]}];
  if[count e ss "no authorization policy is installed"; '"a genuine denial carried the not-installed hint: ",e];
  }]
