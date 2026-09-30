/ tests/obligations.q — the context axis and obligations.
/ .
/ `scope[action;resources;ctx]` is the general decision verb; `authorize` and `entitled` are its published
/ shortcuts. This suite pins the three things that make the general form safe:
/ .
/   1. a policy may only narrow an axis the CALLER declared, so `authorize` — which declares none — can
/      never be handed an obligation it has no way to apply;
/   2. a narrowing carries the same type the caller declared, because a duration where a timestamp was
/      declared reads as nanos-since-2000 and silently passes every row;
/   3. the shortcuts' contracts do not move, at either policy rank.
/ .
/ Helpers live under `.o.` for the same reason the shared ones live under `.t.`: the suite loads both
/ modules FLAT, so an unprefixed name would shadow a module global.

/ ---- fixtures ------------------------------------------------------------------------------------
/ Grow an obligation dict with `o:o,(enlist `k)!enlist v`. NOT `o,:` and NOT `o[`k]:` — both amend a value
/ list that has gone uniformly typed, and signal 'type as soon as a second axis has a different type. This
/ is the idiom a real policy has to use, so the fixtures use it too.
.o.obl:{[k;v] ((),k)!v};

/ A context-aware policy: defers the allow/deny to the installed engine, then narrows.
/ `clip` is the entitled-window start it imposes whenever the caller declared `from`.
.o.clip:2026.05.01D0;
.o.ctxPolicy:{[p;a;rs;ctx]
  ok:decide[p;a;] each rs;
  if[not any ok; :`allowed`obligations!(0b; emptyCtx)];
  o:emptyCtx;
  if[not all ok; o:o,.o.obl[`resources; enlist rs where ok]];
  if[`from in key ctx; if[ctx[`from] < .o.clip; o:o,.o.obl[`from; enlist .o.clip]]];
  `allowed`obligations`reason!(1b; o; "entitled window starts 2026.05.01") };

/ A policy that answers with a fixed obligation set, for the refusal checks.
.o.returning:{[o] {[o;p;a;rs;ctx] `allowed`obligations!(1b; o)}[o]};

/ Grants + a login mapping that put `.t.u` in `traders`, then install a policy.
.o.arrange:{[pol]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  grant[`traders;`read;`ref];
  grant[`traders;`assert;`kx.identity];
  setLoginGroups[(enlist .t.u)!enlist `traders];
  setPolicy pol; };

/ ---- 1. the shortcuts are the general verb ------------------------------------------------------
runTest[`scopeWithNoContextMatchesAuthorize; {[]
  .o.arrange policySpec[];
  / allowed: scope returns no obligations at all, because nothing was narrowed
  o:scope[`read;`data.trades;::];
  if[count o; '"an unnarrowed request carried obligations: ", -3!o];
  / refused: both verbs refuse the same request, and scope names the same target
  .t.mustSignal[{[] scope[`read;`data.secret;::]}; "data.secret"];
  .t.mustDeny[{[] authorize[`read;`data.secret]}];
  }]

runTest[`scopeOverManyResourcesMatchesEntitled; {[]
  .o.arrange policySpec[];
  rs:`data.trades`data.secret`ref.venues`other;
  o:scope[`read;rs;::];
  if[not `data.trades`ref.venues ~ o`resources;
    '"the scope subset disagreed with entitled: ", -3!o];
  if[not (o`resources) ~ entitled[`read;rs];
    '"scope and entitled disagreed: ",(-3!o`resources)," vs ",-3!entitled[`read;rs]];
  }]

runTest[`aScalarPolicyStillAnswersAPluralRequest; {[]
  / the lift is the per-resource loop entitled has always run, so a rank-3 policy needs no vector protocol
  .t.reset[];
  setPolicy[{[p;a;r] r in `data.trades`ref.venues}];
  o:scope[`read;`data.trades`data.secret`ref.venues;::];
  if[not `data.trades`ref.venues ~ o`resources; '"the scalar lift subset was wrong: ", -3!o];
  }]

/ `authorize`'s comment says "one resource, no declared context, so no obligation can reach it" — but
/ `resources` is ALWAYS implicitly declared (decideRequest's `decl`), so that only holds for a SCALAR
/ resource. Handed a vector, `authorize` discards scope's obligations and `liftScalar`'s `any ok`
/ reports allow, so a PARTIAL match silently succeeds. Every in-repo caller passes a scalar, so this is
/ a public-API hazard rather than a live bug.
/ .
/ `authorize` answers a boolean, so it cannot express "some of these": a request it can only partly
/ satisfy has to be refused. That is what this asserts (finding context-axis #4, closed by routing the
/ decision through closeDecision).
runTest[`authorizeRefusesAPartialVectorMatch; {[]
  .t.reset[];
  setPolicy[{[p;a;r] r in enlist `data.trades}];
  .t.mustDeny[{[] authorize[`read;`data.trades`data.secret]}];
  / the single-resource form for the denied resource already refuses correctly
  .t.mustDeny[{[] authorize[`read;`data.secret]}];
  }]

/ ---- 2. the narrowing rule ----------------------------------------------------------------------
runTest[`authorizeCannotReceiveAnObligation; {[]
  / authorize declares no context, so a policy narrowing anything must refuse rather than have its
  / narrowing silently dropped. This is the whole reason the rule is keyed on what the CALLER declared.
  .t.reset[];
  setPolicy .o.returning .o.obl[`from; enlist .o.clip];
  .t.mustSignal[{[] authorize[`read;`data.trades]}; "undeclared axis"];
  }]

runTest[`obligationOnAnUndeclaredAxisIsRefused; {[]
  .t.reset[];
  setPolicy .o.returning .o.obl[`region; enlist `emea];
  .t.mustSignal[{[] scope[`read;`data.trades;.o.obl[`from; enlist .o.clip]]}; "undeclared axis"];
  }]

runTest[`declaringTheAxisUnlocksTheNarrowing; {[]
  / the same policy that was refused above succeeds once the caller declares the axis: declaring more
  / context can only ever unlock a narrowing, never lose one
  .o.arrange .o.ctxPolicy;
  o:scope[`read;`data.trades;.o.obl[`from; enlist 2026.01.01D0]];
  if[not .o.clip ~ o`from; '"the window was not clipped: ", -3!o];
  }]

runTest[`aNarrowingInsideTheDeclaredRangeIsLeftAlone; {[]
  .o.arrange .o.ctxPolicy;
  o:scope[`read;`data.trades;.o.obl[`from; enlist 2026.07.01D0]];
  if[count o; '"a request already inside the entitled window was narrowed anyway: ", -3!o];
  }]

/ ---- 3. the type rule — a silent fail-open, not a crash -----------------------------------------
runTest[`durationWhereATimestampWasDeclaredIsRefused; {[]
  / `2026.08.20D09:00:00 > 900000000000` is 1b: q reads the long as nanos-since-2000. So a policy meaning
  / "clip to 15 minutes" that returns a duration would clip to 2000.01.01D00:15 and pass EVERY row, with
  / nothing signalled anywhere. Exact type equality is the only thing standing between us and that.
  .t.reset[];
  setPolicy .o.returning .o.obl[`from; enlist 900000000000];
  .t.mustSignal[{[] scope[`read;`data.trades;.o.obl[`from; enlist 2026.01.01D0]]}; "type mismatch"];
  }]

runTest[`narrowingAListToAnAtomIsRefused; {[]
  / list-ness is part of the declared type, so an engine narrowing to one value returns `enlist `A` and
  / every caller's applier keeps the same shape
  .t.reset[];
  setPolicy .o.returning .o.obl[`syms; enlist `AAPL];
  .t.mustSignal[{[] scope[`read;`data.trades;.o.obl[`syms; enlist `AAPL`MSFT]]}; "type mismatch"];
  }]

/ ---- 4. widening ---------------------------------------------------------------------------------
runTest[`wideningADeclaredListIsRefused; {[]
  / the seam's return value is authoritative — the caller queries what comes back — so a policy handing
  / back MORE than was asked for would be obeyed. On a list axis that is checkable without knowing what
  / the axis means, so it is checked.
  .t.reset[];
  setPolicy .o.returning .o.obl[`syms; enlist `AAPL`MSFT`TSLA];
  .t.mustSignal[{[] scope[`read;`data.trades;.o.obl[`syms; enlist `AAPL`MSFT]]}; "widened"];
  }]

runTest[`aResourceObligationCannotExceedTheRequest; {[]
  .t.reset[];
  setPolicy .o.returning .o.obl[`resources; enlist `data.trades`data.secret];
  .t.mustSignal[{[] scope[`read;`data.trades;::]}; "widened"];
  }]

/ ---- 5. the resource axis's one special rule -----------------------------------------------------
runTest[`emptyResourceNarrowingIsARefusal; {[]
  / narrowed to nothing is a refusal, not an allow that yields nothing. This is what keeps the scalar and
  / plural cases uniform: for one resource, excluding it IS the denial.
  .t.reset[];
  setPolicy .o.returning .o.obl[`resources; enlist `symbol$()];
  .t.mustDeny[{[] scope[`read;`data.trades;::]}];
  }]

/ ---- 6. context shape ----------------------------------------------------------------------------
runTest[`omittedContextIsAcceptedAsNil; {[]
  .t.reset[]; .t.allowAll[];
  if[count scope[`read;`data.trades;::]; '"(::) was not treated as an empty context"];
  }]

runTest[`bothEmptyDictFlavoursAreAcceptedAsNoContext; {[]
  / `type key ()!()` is 0h while `` type key (`symbol$())!() `` is 11h, and `()!() ~ (`symbol$())!()`
  / SIGNALS 'length. Normalising both means the seam cannot behave differently depending on which flavour
  / a caller happened to build.
  .t.reset[]; .t.allowAll[];
  if[count scope[`read;`data.trades;()!()]; '"the generic empty dict was not accepted"];
  if[count scope[`read;`data.trades;(`symbol$())!()]; '"the typed empty dict was not accepted"];
  }]

runTest[`duplicateKeyedContextIsRejected; {[]
  / `` d:(`a`a)!(1 2) `` updated at `` `a `` keeps the STALE second value, so an applier iterating the keys
  / would apply the un-narrowed one. Refuse rather than half-apply.
  .t.reset[]; .t.allowAll[];
  .t.mustSignal[{[] scope[`read;`data.trades;(`from`from)!(2026.01.01D0;2026.02.01D0)]}; "duplicate keys"];
  }]

runTest[`keyedTableIsNotAContext; {[]
  / a keyed table is also type 99h, so a naive shape check would let one through
  .t.reset[]; .t.allowAll[];
  .t.mustSignal[{[] scope[`read;`data.trades;([k:1 2]v:3 4)]}; "keyed table"];
  }]

runTest[`reservedResourcesContextKeyIsRejected; {[]
  / `resources` is always declared implicitly, so redeclaring it in the context would give two sources for
  / one axis
  .t.reset[]; .t.allowAll[];
  .t.mustSignal[{[] scope[`read;`data.trades;.o.obl[`resources; enlist `data.trades]]}; "reserved"];
  }]

/ Every shape check above drives `scope`. `explainScope` runs the identical normaliseCtx/ctxFault
/ sequence from its own duplicated call site, with its own error prefix — so a caller inspecting a
/ malformed context gets told which verb refused it. Neither half was pinned.
runTest[`explainScopeRejectsAMalformedContextWithItsOwnPrefix; {[]
  .t.reset[]; .t.allowAll[];
  e:.t.trap[{[] explainScope[.t.subj[`traders];`read;`data.trades;([k:1 2]v:3 4)]}];
  if[not 10h=type e; '"explainScope did not signal on a keyed-table context: ",-3!e];
  if[not count e ss "kx.auth.explain:"; '"explainScope did not use its own error prefix: ",e];
  if[not count e ss "keyed table"; '"explainScope signalled for the wrong reason: ",e];
  }]

/ ---- 7. a malformed policy answer is a named refusal --------------------------------------------
runTest[`malformedDecisionIsANamedRefusal; {[]
  / a rank-4 policy answering with a boolean would otherwise fail closed by accident, as a bare 'type from
  / somewhere inside the seam, and an operator would have nothing to go on
  .t.reset[];
  setPolicy[{[p;a;rs;ctx] 1b}];
  .t.mustSignal[{[] scope[`read;`data.trades;::]}; "decision dictionary"];
  setPolicy[{[p;a;rs;ctx] (enlist `allowed)!enlist 1b}];
  .t.mustSignal[{[] scope[`read;`data.trades;::]}; "`allowed and `obligations"];
  setPolicy[{[p;a;rs;ctx] `allowed`obligations!(01b; emptyCtx)}];
  .t.mustSignal[{[] scope[`read;`data.trades;::]}; "boolean atom"];
  }]

/ ---- 8. the installer ----------------------------------------------------------------------------
runTest[`setPolicyAcceptsBothRanks; {[]
  .t.reset[];
  setPolicy[{[p;a;r] 1b}];
  if[3<>policyRank; '"a rank-3 policy was not recorded as rank 3"];
  setPolicy[{[p;a;rs;ctx] `allowed`obligations!(1b; emptyCtx)}];
  if[4<>policyRank; '"a rank-4 policy was not recorded as rank 4"];
  }]

runTest[`setPolicyRejectsAnImpossibleRank; {[]
  .t.reset[];
  before:policyRank;
  .t.mustSignal[{[] setPolicy[{[a;b] 1b}]}; "3 arguments"];
  if[before<>policyRank; '"a refused setPolicy still moved policyRank"];
  }]

/ The projection branch is the one rankOf's own comment names as the design motivation — a host
/ installing `myPolicy[config]` must not be read as the other rank and then fail with a bare 'rank on
/ the first decision. The tests above pass plain lambdas only, so `104h` was never asserted on.
runTest[`rankOfDetectsAProjectionsRemainingArity; {[]
  .t.reset[];
  / `f[;;;;`c]` is the comment's own example: one argument bound, four holes, so four are still wanted.
  f:{[a;b;c;d;e] a+b+c+d+e};
  p:f[;;;;`c];
  if[4<>rankOf p; '"a projection with four holes was not read as wanting four: ",-3!rankOf p];
  / the .z.s recursion: a projection OF that projection, one more bound, wants one fewer
  if[3<>rankOf p[1;;;]; '"a nested projection's remaining arity was wrong: ",-3!rankOf p[1;;;]];
  / and the installer records it — every rank-4 setPolicy above installs a plain lambda, not a projection
  setPolicy .o.returning .o.obl[`from; enlist 2026.01.01D0];
  if[4<>policyRank; '"setPolicy did not record a projection as rank 4"];
  }]

/ setPolicyRejectsAnImpossibleRank covers a DECIDABLE wrong rank (two arguments). A composition or a
/ primitive is a different case: rankOf cannot count what it wants, and the seam deliberately installs
/ it at rank 3 rather than refusing — that is what such a policy did before the seam existed, and
/ guessing 4 would change a working deployment's meaning.
runTest[`setPolicyDefaultsUndecidableFunctionsToRankThree; {[]
  .t.reset[];
  comp:not {[p;a;r] 0b}@;
  if[not null rankOf comp; '"expected rankOf to report 0N for a composition, got ",-3!rankOf comp];
  setPolicy comp;
  if[3<>policyRank; '"an undecidable policy did not default to rank 3, got ",-3!policyRank];
  }]

/ ---- 9. explain — an obligation you can inspect, not only obey ----------------------------------
runTest[`explainReportsANarrowingWithoutSignalling; {[]
  .o.arrange .o.ctxPolicy;
  d:explainScope[.t.subj`traders;`read;`data.trades;.o.obl[`from; enlist 2026.01.01D0]];
  if[not d`allowed; '"explain refused a request scope allows"];
  if[not .o.clip ~ d[`obligations;`from]; '"explain did not report the clipped window: ", -3!d];
  if[not "" ~ d`denial; '"an allowed decision carried denial text"];
  }]

runTest[`explainReportsARefusalWithItsDenialText; {[]
  .o.arrange .o.ctxPolicy;
  d:explainScope[.t.subj`traders;`delete;`data.trades;::];
  if[d`allowed; '"explain allowed a request scope refuses"];
  if[not count d`denial; '"a refusal carried no denial text"];
  if[not count (d`denial) ss "data.trades"; '"the denial text did not name the target: ",d`denial];
  }]

runTest[`explainSurfacesThePolicysReason; {[]
  .o.arrange .o.ctxPolicy;
  d:explainScope[.t.subj`traders;`read;`data.trades;.o.obl[`from; enlist 2026.01.01D0]];
  if[not count (d`reason) ss "entitled window"; '"the policy's reason did not survive: ", -3!d`reason];
  }]

/ Every denial test in this suite refuses ONE resource, so denialText's plural arm — a space-joined
/ list of everything that was asked for — had never formatted anything. An operator reading a refused
/ batch needs to see which batch it was.
runTest[`denialTextListsAllRequestedResourcesWhenWhollyRefused; {[]
  .t.reset[];
  setPolicy[{[p;a;rs;ctx] `allowed`obligations!(0b; emptyCtx)}];
  d:explainScope[.t.subj[`traders];`read;`data.trades`data.secret;::];
  if[d`allowed; '"precondition failed: the policy was meant to refuse"];
  if[not count (d`denial) ss "data.trades data.secret";
    '"the plural denial did not list every requested resource: ",d`denial];
  }]

runTest[`explainIsPureAndNeedsNoBoundPrincipal; {[]
  / the same split kx.rbac.check makes: enforcement reads the principal in effect, inspection is handed
  / one. A caller-supplied subject on an ENFORCING verb would be a privilege-escalation primitive.
  .o.arrange policySpec[];
  d:explainScope[.t.subj`nobody;`read;`data.trades;::];
  if[d`allowed; '"a groupless subject was allowed"];
  d2:explainScope[.t.subj`traders;`read;`data.trades;::];
  if[not d2`allowed; '"an explicitly-passed entitled subject was refused"];
  }]

/ ---- 10. the control plane must survive a context-aware policy ----------------------------------
runTest[`assertGateSurvivesAContextAwarePolicy; {[]
  / bind, the HTTP assert gate, gateEval and kx.rbac's admin gate cannot declare a context — three of them
  / are the control plane. Calling the policy slot with three arguments would hand a rank-4 policy a
  / PROJECTION and signal 'type inside bind, so they go through the rank-agnostic boolean helper.
  .o.arrange .o.ctxPolicy;
  bind[`sub`groups!(`alice; enlist `traders)];
  if[not `alice ~ (current[])`sub; '"bind did not take effect under a rank-4 policy"];
  .t.reset[];
  }]

runTest[`anUnappliableObligationRefusesTheAssertGate; {[]
  / the gate cannot apply a narrowing, so a policy that would narrow its decision must be refused rather
  / than have the narrowing ignored
  .t.reset[];
  setPolicy .o.returning .o.obl[`resources; enlist `symbol$()];
  .t.mustDeny[{[] bind[`sub`groups!(`alice; enlist `traders)]}];
  }]

/ The comment above names four control-plane sites, but only `bind` is ever driven under a rank-4
/ policy — and the four do NOT agree. `bind` and `httpMayAssert` go through the rank-agnostic `allows`
/ helper, whose `0=count obligations` conjunct fails closed on an obligation they cannot apply;
/ `gateEval` goes through `authorize`, which DISCARDS obligations, so it proceeds instead.
/ .
/ A gate that cannot apply a narrowing must refuse rather than ignore it — that rule is already stated
/ for `bind` in the check above, and it cannot be true of only some of the gates. So this asserts the
/ whole invariant: every control-plane site fails closed. The `gateEval` half was the one that failed
/ (finding context-axis #3). `kx.rbac.requireAdmin`, the fourth site, is unreachable in-process — `.z.w`
/ is 0, so its local-bypass returns before the policy is consulted — so it is out of this suite's reach
/ by construction.
runTest[`everyControlPlaneSiteFailsClosedOnAnUnappliableObligation; {[]
  .t.resetHttp[];
  / an obligation naming exactly the resource that was asked for: nothing is narrowed away, but the
  / obligation set is non-empty, which is what an unappliable narrowing looks like to a boolean gate
  setPolicy .o.returning .o.obl[`resources; enlist enlist `kx.identity];
  .t.mustDeny[{[] bind[`sub`groups!(`alice; enlist `traders)]}];
  / httpMayAssert ANSWERS a boolean rather than signalling, so assert on the value
  if[httpMayAssert[]; '"the HTTP assert gate allowed an unappliable obligation"];
  / gateEval must refuse too. Asserted as "did not proceed" rather than via .t.mustDeny, so that any
  / refusal shape satisfies it — this must not bake in an assumption about how the fix is written.
  setPolicy .o.returning .o.obl[`resources; enlist enlist `kx.q];
  if[`ok ~ .t.trap[{[] gateEval[{[x] value x}; "1+1"]}];
    '"gateEval proceeded despite an obligation it cannot apply"];
  .t.reset[];
  }]

/ ---- 11. the shortcuts under a context-aware policy ---------------------------------------------
runTest[`entitledIsUnchangedUnderAContextAwarePolicy; {[]
  .o.arrange .o.ctxPolicy;
  got:entitled[`read;`data.trades`data.secret`ref.venues];
  if[not `data.trades`ref.venues ~ got; '"entitled changed shape under a rank-4 policy: ", -3!got];
  / and it still answers with an empty vector of the right type rather than signalling
  setLoginGroups[(enlist .t.u)!enlist `nobody];
  empty:entitled[`read;`data.trades`other];
  if[not 11h = type empty; '"an empty subset lost its symbol type: ", -3!type empty];
  if[count empty; '"a subject with no grants was entitled to something"];
  }]

/ ---- 12. the flat-load namespace ----------------------------------------------------------------
runTest[`flatLoadCollisionSetIsExactlyExport; {[]
  / test.q loads kx.auth flat FIRST and kx.rbac SECOND, and q resolves globals at call time — so a name
  / defined by both is silently the rbac one, including inside kx.auth's own verbs. `export` is the only
  / such name, and it is harmless solely because test.q captures `.kx.auth:export` between the two loads.
  / A third module, or one more clash, turns that into a lottery. This is why the new seam privates are
  / `decideRequest` and `allows` rather than the `decide` that reads best: kx.rbac already owns `decide`.
  a:`bound`policy`policyRank`emptyCtx`promote`shapeFault`authorize`entitled`scope`explainScope`decideRequest`closeDecision`allows`liftScalar`dictFault`ctxFault`normaliseCtx`denialText;
  r:`grantStore`decide`covers`splitPath`check`explain`grants`verify`policySpec`applicable;
  clash:a inter r;
  / `not `symbol$() ~ clash` would parse right-to-left as ``symbol$(() ~ clash)`` — casting a boolean to a
  / symbol. Count it instead of reaching for an empty-vector literal comparison.
  if[count clash;
    '"kx.auth and kx.rbac now share a root name, so the flat load silently resolves it to rbac's: ",
      " " sv string clash];
  }]

/ ---- 13. denialText's interpolation --------------------------------------------------------------
/ denialText (init.q:224-231) builds its message by interpolating the subject, the resource list and the
/ policy's `reason` straight into a string, then appending the "no policy installed" hint LAST. Four
/ defects follow from that one construction, and they fail at three different expressions — so this is
/ one function (one code site, one fix to make) with four assertions (no single fix covers them all:
/ symbolising the subject fixes (a) and leaves (b) untouched, and neither goes near (d)). Findings
/ context-axis #7, #9, #14 and kx.auth core #4.
runTest[`denialTextSurvivesHostileInterpolation; {[]
  / (a) a char-vector `sub` — string["alice"] is a general LIST of one-char strings, so the whole
  / message becomes a general list and `explain` emits a JSON char array instead of a sentence.
  .t.reset[];
  setPolicy[{[p;a;r] 0b}];
  d:explainScope[`sub`groups!("alice"; enlist `t);`read;`data.trades;::];
  if[not 10h=type d`denial;
    '"a char-vector sub made the denial a general list rather than a string: ", -3!type d`denial];

  / (b) a general-list `sub` — exactly what .j.k yields for "sub":["a","b"] — used to reach denialText and
  / make the DENIAL SIGNAL 'stype, because you cannot signal a general list. promote now refuses that
  / shape at the boundary (rebind.q's promoteRefusesEachMalformedShapeByName), so over HTTP the header is
  / answered 400 and the handler NEVER RUNS: the hostile subject cannot reach denialText at all.
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and r~`kx.identity}];
  .t.httpDenial:`nothingRan;
  r:serveHttp[{[x] .t.httpDenial:.t.trap[{[] scope[`read;`data.trades;::]}]; `ok};
              .t.req "{\"sub\":[\"a\",\"b\"],\"groups\":[\"t\"]}"];
  if[not `nothingRan ~ .t.httpDenial; '"a JSON-array sub reached the handler instead of being refused at the boundary"];
  if[not $[10h=type r; r like "HTTP/1.1 400*"; 0b]; '"a JSON-array sub was not answered 400: ",-3!r];

  / (c) a SYMBOL `reason` from a rank-4 policy signals 'stype at a different expression again — the
  / reason is concatenated without being stringified, and denialText's `count d`reason` guard passes
  / for a symbol.
  .t.reset[];
  setPolicy[{[p;a;rs;ctx] `allowed`obligations`reason!(0b; emptyCtx; `insufficient)}];
  e:.t.trap[{[] scope[`read;`data.trades;::]}];
  if[not e like "denied:*"; '"a symbol reason broke the denial message: ",e];

  / (d) q truncates a signalled string at exactly 254 bytes, and the bootstrap hint is appended LAST —
  / so a plural denial deletes the one line telling a host that setPolicy[] was never called. The single
  / -resource case is pinned green by rbac.q's anUninstalledPolicyExplainsItselfOnDenial; this is its
  / plural sibling, and it is the assertion that a "shorten the resource list" fix must satisfy.
  .t.reset[];
  setPolicy[denyAll];
  e:.t.trap[{[] scope[`read;`$"data.r",/:string til 40;::]}];
  if[not count e ss "setPolicy";
    '"the setPolicy hint was truncated out of a plural denial (",(string count e)," bytes): ",e];
  }]

/ ---- 14. the closed decision is ONE rule, shared -------------------------------------------------
/ `allows` (bind, httpMayAssert) and `authorize` (gateEval, protected functions, kx.rbac.requireAdmin) are
/ the two entry points onto decideRequest that cannot apply a narrowing. The fail-closed rule — allowed
/ AND nothing left to apply — used to be written in each; now both read closeDecision, so it cannot drift.
runTest[`closeDecisionIsTheOneRuleBothGatesRead; {[]
  .t.reset[];
  / an obligation naming exactly what was asked for: nothing narrowed away, but not appliable by a gate
  setPolicy .o.returning .o.obl[`resources; enlist enlist `data.trades];
  p:.t.subj[`traders];
  d:closeDecision[p;`read;`data.trades];
  if[d`allowed; '"closeDecision left an obligation-carrying allow open"];
  if[not count (d`reason) ss "resources"; '"the closed decision did not name the narrowed axis: ",-3!d];
  if[allows[p;`read;`data.trades]; '"allows disagreed with closeDecision"];
  e:.t.trap[{[] authorize[`read;`data.trades]}];
  if[not $[10h=type e; "denied"~6#e; 0b]; '"authorize did not refuse through denialText: ",-3!e];
  if[not count e ss "not permitted read on data.trades"; '"authorize's refusal lost the <action> on <resource> form: ",e];
  if[not count e ss "obligation(s) on resources"; '"authorize's refusal did not carry the closed reason: ",e];
  / and the OPEN verbs are untouched: scope hands the obligation over, explain reports the allow
  if[not (enlist `data.trades) ~ (scope[`read;`data.trades;::])`resources; '"scope stopped returning the obligation"];
  if[not (explainScope[p;`read;`data.trades;::])`allowed; '"explain closed a decision it should only report"];
  }]

/ A policy's own denial reason still reaches the caller unchanged — closing only ever ADDS a reason to an
/ allow it has to refuse, it never overwrites a refusal's.
runTest[`closeDecisionKeepsAPolicysOwnDenialReason; {[]
  .t.reset[];
  setPolicy[{[p;a;rs;ctx] `allowed`obligations`reason!(0b; emptyCtx; "quota exhausted")}];
  .t.mustSignal[{[] authorize[`read;`data.trades]}; "quota exhausted"];
  d:closeDecision[.t.subj[`traders];`read;`data.trades];
  if[not "quota exhausted" ~ d`reason; '"the policy's reason was rewritten: ",-3!d`reason];
  }]
