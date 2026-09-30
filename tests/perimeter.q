/ tests/perimeter.q — the HTTP asserter backstop and the opt-in qIPC perimeter gate.
/ .
/ Both qIPC and HTTP authorize assertion against the caller's login. Perimeter-only trust is an explicit,
/ audited opt-out for HTTP.
/ .
/ WHAT THIS SUITE CANNOT REACH. In-process there is no real .z.pg/.z.ps dispatch and no real HTTP socket,
/ so these drive serveHttp / gateEval directly. The live versions belong in the demo client, which has
/ real connections and a real second login.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ Restore the HTTP posture as well as the usual state.
.t.resetHttp:{[] httpTrustPerimeter::0b; reqPrincipal::(::); logins::(`symbol$())!(); .t.reset[]; };

/ An HTTP request the way kdb+ presents it: (requestText; headerDict). Header keys are symbols and are
/ matched case-insensitively, so this deliberately uses a mixed-case name.
/ NB `enlist` on the KEY as well as the value — `atom!list` is not a dict and 'type's.
.t.req:{[json] ("GET /"; (enlist `$"X-Kx-Principal")!enlist json)};
.t.reqNoHeader:{[] ("GET /"; (enlist `Accept)!enlist "*/*")};

/ A prior handler that reports the principal in effect when it ran — the only way to observe what
/ serveHttp bound for the duration of the request.
.t.echoPrincipal:{[x] $[(::)~current[]; `none; (current[])`sub]};

/ A refusal ANSWERS with 403 rather than signalling: serveHttp wraps the host handler, so a signal would
/ reach the client as a bare 500 with no host able to correct it. Assert on the response, not on a throw.
.t.mustRefuse:{[f;fragment]
  r:@[f; ::; {[e] '"serveHttp signalled instead of answering 403: ",e}];
  if[not 10h=type r; '"expected an HTTP response, got ", -3!r];
  if[not r like "HTTP/1.1 403 Forbidden*"; '"expected 403, got: ",40 sublist r];
  if[not any r ss fragment; '"403 body did not mention \"",fragment,"\": ",r];
  }

/ ---- 1. the HTTP assert gate ----------------------------------------------------------------------
/ A proxy login with no `assert grant is refused, exactly as an unauthorised qIPC caller is.
runTest[`httpHeaderRefusedWithoutAnAssertGrant; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];
  .t.mustRefuse[{[] serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\"}"]}; "not permitted to assert identity over HTTP"];
  }]

/ Being AUTHENTICATED must never imply being permitted to assert — that is the exact mistake the
/ backstop exists to prevent, and it is why the grant is consulted rather than the connection trusted.
runTest[`authenticatedButUngrantedProxyCannotAssert; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `someGroup];        / mapped, so it has an identity ...
  setPolicy[{[p;a;r] (a~`read) and r~`data.trades}];      / ... but holds no assert grant
  .t.mustRefuse[{[] serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\"}"]}; "not permitted to assert"];
  }]

/ With the grant, reached through the same login map qIPC uses, the header is honoured.
runTest[`grantedProxyMayAssertOverHttp; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and `proxies in p`groups}];
  r:serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\",\"groups\":[\"trader\"]}"];
  if[not `alice ~ r; '"the asserted principal was not in effect during the request, got ", -3!r];
  }]

/ A refused request must leave NOTHING bound — an unauthorised asserter must not be able to put any
/ principal in effect, not even one that a later authorize[] would have denied.
runTest[`refusedHttpAssertLeavesNoPrincipalInEffect; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];
  .t.mustRefuse[{[] serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\"}"]}; "not permitted to assert"];
  if[not (::)~reqPrincipal; '"a refused HTTP assert left a request principal behind"];
  }]

/ A successful request must also clear reqPrincipal afterward — refusedHttpAssertLeavesNoPrincipalInEffect
/ only proves this for the REFUSED path; this is the successful-path half of the same guarantee.
runTest[`reqPrincipalClearedAfterASuccessfulRequest; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and `proxies in p`groups}];
  r:serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\"}"];
  if[not `alice ~ r; '"precondition failed: the request did not see the asserted principal"];
  if[not (::)~reqPrincipal; '"a successful HTTP request left a request principal behind"];
  }]

/ A request with NO principal header is not an assertion, so the gate must not fire — it simply runs
/ with no request principal, and the subject rule then falls back to the caller's own login.
runTest[`requestWithNoHeaderIsNotGated; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];                                / nobody may assert anything
  r:serveHttp[.t.echoPrincipal; .t.reqNoHeader[]];
  if[not .t.u ~ r; '"a header-less request did not fall back to the caller's own login, got ", -3!r];
  }]

/ A request tuple shorter than 2 elements (no header dict at all — the tuple is just (requestText;))
/ takes serveHttp's own defensive default to an empty header dict, rather than signalling on the
/ missing index. Every other fixture in this file supplies exactly 2 elements, so this was untested.
.t.reqShort:{[] enlist "GET /"};
runTest[`shortRequestTupleFallsBackToNoPrincipal; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];                                / nobody may assert anything
  r:serveHttp[.t.echoPrincipal; .t.reqShort[]];
  if[not .t.u ~ r; '"a short request tuple did not fall back to the caller's own login, got ", -3!r];
  if[not (::)~reqPrincipal; '"a short request tuple left a request principal behind"];
  }]

/ A proxy that appends its own header instead of replacing a client-supplied one hands q TWO
/ x-kx-principal entries, and resolving by first match would bind the client's forged value. That is
/ constraint 2's forgery, and while q cannot verify the strip happened it can refuse the ambiguity a
/ missing strip produces. The proxy IS granted here, so a refusal proves the guard fired ahead of the
/ assertion succeeding — not that the caller merely lacked the grant.
/ NB `enlist` on neither: two keys, two values. Mixed case proves the count is case-insensitive.
.t.reqDup:{[j1;j2] ("GET /"; (`$("X-Kx-Principal";"x-kx-principal"))!(j1;j2))};
runTest[`duplicatePrincipalHeadersAreRefused; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and `proxies in p`groups}];
  .t.mustRefuse[{[] serveHttp[.t.echoPrincipal;
    .t.reqDup["{\"sub\":\"forged\",\"groups\":[\"trader\"]}"; "{\"sub\":\"real\"}"]]}; "not stripping"];
  if[not (::)~reqPrincipal; '"a refused duplicate-header request left a principal behind"];
  }]

/ ---- 2. perimeter-only trust: explicit, and audited ----------------------------------------------
runTest[`perimeterTrustAllowsAssertionWithoutAGrant; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];                                / no assert grant anywhere
  setHttpTrustPerimeter[1b];
  r:serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\"}"];
  if[not `alice ~ r; '"perimeter trust did not honour the header, got ", -3!r];
  }]

/ The grant path must be preferred, so a correctly-configured deployment never relies on the fallback and
/ never emits its warning.
runTest[`perimeterTrustIsNotConsultedWhenAGrantExists; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and `proxies in p`groups}];
  setHttpTrustPerimeter[1b];
  if[not httpMayAssert[]; '"a granted caller was refused"];
  / remove the grant and it must fall through to perimeter trust, proving the order
  setPolicy[{[p;a;r] 0b}];
  if[not httpMayAssert[]; '"perimeter trust did not act as the fallback"];
  setHttpTrustPerimeter[0b];
  if[httpMayAssert[]; '"perimeter trust stayed on after being turned off"];
  }]

runTest[`setHttpTrustPerimeterRejectsNonBoolean; {[]
  .t.resetHttp[];
  .t.mustSignal[{[] setHttpTrustPerimeter[1]}; "expects a boolean"];
  .t.mustSignal[{[] setHttpTrustPerimeter[`yes]}; "expects a boolean"];
  }]

/ The default is the SAFE one. A deployment that never thinks about this gets the gated behaviour.
runTest[`perimeterTrustDefaultsOff; {[]
  .t.resetHttp[];
  if[httpTrustPerimeter; '"perimeter trust is on by default — the unsafe posture must be opt-in"];
  }]

/ ---- 3. the qIPC perimeter gate (coarse, opt-in) -------------------------------------------------
/ Requires a valid subject AND the capability grant `eval on `kx.q. Nothing else — it must not parse the
/ q it gates.
runTest[`perimeterGateRefusesWithoutTheEvalGrant; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];
  .t.mustDeny[{[] gateEval[{[x] value x}; "1+1"]}];
  }]

runTest[`perimeterGateAllowsWithTheEvalGrant; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `power];
  setPolicy[{[p;a;r] (a~`eval) and (r~`kx.q) and `power in p`groups}];
  if[not 2 ~ gateEval[{[x] value x}; "1+1"]; '"a granted caller could not evaluate"];
  }]

/ The grant is for `eval on `kx.q specifically — an unrelated grant must not open the perimeter.
runTest[`perimeterGateIsNotOpenedByAnUnrelatedGrant; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `readers];
  setPolicy[{[p;a;r] (a~`read) and r~`data.trades}];
  .t.mustDeny[{[] gateEval[{[x] value x}; "1+1"]}];
  }]

/ It composes rather than clobbers: the prior handler still decides what running the message MEANS.
runTest[`perimeterGateComposesWithThePriorHandler; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `power];
  setPolicy[{[p;a;r] (a~`eval) and r~`kx.q}];
  if[not `wrapped ~ gateEval[{[x] `wrapped}; "1+1"];
    '"the prior handler was not consulted — the gate clobbered instead of composing"];
  }]

/ It does NOT parse the q it gates. A caller holding `eval:kx.q may run anything; a caller without it may
/ run nothing. Pin that so nobody "improves" it into a half-parser that looks like enforcement.
runTest[`perimeterGateDoesNotInspectTheQItGates; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `power];
  setPolicy[{[p;a;r] (a~`eval) and r~`kx.q}];
  / a "dangerous"-looking expression and a harmless one are treated identically — by design
  if[not 2 ~ gateEval[{[x] value x}; "1+1"]; '"the harmless expression was refused"];
  if[not `sym ~ gateEval[{[x] value x}; "`sym"]; '"a different expression was treated differently"];
  }]

/ The coarse gate sees EVERY sync request, including bind[] itself — the unit-level mirror of the demo's
/ theCoarseGateAlsoStopsBind (q-scripts/client.q). gateEval is message-blind, so this drives it directly
/ with a bind-shaped source string rather than a real .z.pg dispatch.
runTest[`activatePerimeterGateAlsoAppliesToBind; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  / holding ONLY the assert grant is not enough once the coarse gate is armed
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and `proxies in p`groups}];
  .t.mustSignal[{[] gateEval[{[x] value x}; "bind[`sub`groups!(`alice;enlist `trader)]"]}; "eval on kx.q"];
  / holding BOTH grants, the message-blind gate lets the same call through to bind, which then succeeds
  setPolicy[{[p;a;r] (`proxies in p`groups) and (((a~`assert) and r~`kx.identity) or (a~`eval) and r~`kx.q)}];
  gateEval[{[x] value x}; "bind[`sub`groups!(`alice;enlist `trader)]"];
  if[not `alice ~ (current[])`sub; '"holding both grants did not let the bind through the gate"];
  }]

/ Perimeter gating is SEPARATE from activate[]/activateHttp[] — a deployment that never wants it never
/ touches it, and the export surface must keep the three verbs distinct.
runTest[`perimeterActivationIsASeparateOptIn; {[]
  if[not all `activate`activateHttp`activatePerimeter in key .kx.auth;
    '"the three activation verbs are not all exported separately"];
  if[.kx.auth[`activate] ~ .kx.auth[`activatePerimeter]; '"activate and activatePerimeter are the same verb"];
  }]

runTest[`activationIsIdempotent; {[]
  .t.resetHttp[];
  .t.allowAll[];
  .z.pw:{[u;p] 1b}; .z.po:{[w] `po}; .z.pc:{[w] `pc};
  .z.ph:{[x] `ph}; .z.pp:{[x] `pp};
  .z.pg:{[x] `pg}; .z.ps:{[x] `ps};
  activate[]; activate[];
  activateHttp[]; activateHttp[];
  activatePerimeter[]; activatePerimeter[];
  if[not `po ~ .z.po 1; '"repeated activate wrapped .z.po recursively"];
  if[not `pc ~ .z.pc 1; '"repeated activate wrapped .z.pc recursively"];
  if[not `ph ~ .z.ph enlist `request; '"repeated activateHttp wrapped .z.ph recursively"];
  if[not `pp ~ .z.pp enlist `request; '"repeated activateHttp wrapped .z.pp recursively"];
  if[not `pg ~ .z.pg "1+1"; '"repeated activatePerimeter wrapped .z.pg recursively"];
  if[not `ps ~ .z.ps "1+1"; '"repeated activatePerimeter wrapped .z.ps recursively"];
  }]

/ ---- 4. HTTP-asserted principals decide identically to qIPC/login-space, for the same groups ---------
/ login-space.q already pins qIPC-vs-login-space parity (loginSpaceDecidesIdenticallyToTokenSpace). This
/ is the missing third leg: HTTP, compared against both, over the SAME answer list — not two separate
/ hardcoded-literal checks (that's what the envoy-gateway demo's theSameTokenIsAllowedOverQipcAsOverHttp
/ already does, live but skippable and never diffing the two decisions against each other).
.t.answers:{[] (valid[]; (require[])`groups; (authorize[`read;`data.trades])`groups;
                entitled[`read;`data.trades`data.instruments])};

runTest[`httpAssertedPrincipalDecidesIdenticallyToQipc; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `trader];          / the caller's own login: same groups, may assert
  setPolicy[{[p;a;r] $[(a~`assert) and r~`kx.identity; `trader in p`groups;
                       (`trader in p`groups) and a~`read]}];

  / leg 1 — login space: nothing bound, no request principal
  loginAnswers:.t.answers[];

  / leg 2 — HTTP: answers must be taken INSIDE the handler, the only window reqPrincipal is set
  httpAnswers:serveHttp[{[x] (.t.answers[]; (current[])`sub)}; .t.req "{\"sub\":\"alice\",\"groups\":[\"trader\"]}"];
  if[10h=type httpAnswers; '"the HTTP leg was refused, so no decision was compared: ",40 sublist httpAnswers];
  if[not `alice ~ httpAnswers 1;
    '"the HTTP answers were taken under the caller's own login, not the asserted principal — the comparison would be vacuous"];

  / leg 3 — qIPC: same groups, arriving by bind. Taken LAST: bound shadows the login fallback.
  bind[`sub`groups!(`bob; enlist `trader)];
  ipcAnswers:.t.answers[];

  if[not loginAnswers ~ httpAnswers 0;
    '"a decision differed by TRANSPORT — HTTP has become a special path: ",
      (-3!loginAnswers)," vs ",-3!httpAnswers 0];
  if[not ipcAnswers ~ httpAnswers 0;
    '"an HTTP-asserted principal decided differently from a qIPC-bound one: ",
      (-3!ipcAnswers)," vs ",-3!httpAnswers 0];
  }]

/ ---- 9. a hostile principal header ----------------------------------------------------------------
/ This file's own .t.mustRefuse states the invariant: a refusal must ANSWER, not signal, because a signal
/ out of .z.ph reaches the client as a bare 500 with no host able to correct it. fromJson sits at
/ init.q:445, one line ABOVE the trap at :446 that makes that true — so anything malformed in the header
/ escapes as exactly the 500 the wrapper exists to prevent. Two assertions because the two inputs fail at
/ different expressions: a `99h` type check on the parse result catches the second and not the first.
/ Asserted as "answered 4xx" rather than through .t.mustRefuse, so the check does not presuppose the
/ wording or the exact status the fix picks for its refusal body. Finding kx.auth core #1.
runTest[`hostilePrincipalHeaderAnswersRatherThanSignalling; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and r~`kx.identity}];
  {[j]
    r:@[{[x] serveHttp[.t.echoPrincipal; .t.req x]}; j; {[e] "SIGNALLED: ",e}];
    if[not $[10h=type r; r like "HTTP/1.1 4*"; 0b];
      '"a hostile principal header must be ANSWERED with a 4xx, got: ",
        $[10h=type r; 60 sublist r; -3!r]];
   } each ("{\"sub\":\"alice\",";                / unparseable — truncated object
           "42");                               / parseable, but not an object
  }]

/ ---- 10. serveHttp reentrancy ---------------------------------------------------------------------
/ reqPrincipal is a single global slot that serveHttp unconditionally resets when it returns
/ (init.q:446-448), so a handler that itself calls serveHttp destroys the OUTER request's identity
/ mid-flight — the rest of the outer handler then runs as the connecting login rather than as the
/ principal the gateway asserted. That is deterministic reentrancy, not a race: no concurrency needed
/ to show it, which is why it is testable here while kx.rbac #8's race is not. Finding kx.auth core #10.
runTest[`nestedServeHttpPreservesTheOuterPrincipal; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and r~`kx.identity}];
  got:serveHttp[{[x]
      serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"bob\"}"];   / an inner request, then carry on
      .t.echoPrincipal x};
    .t.req "{\"sub\":\"alice\"}"];
  if[10h=type got; '"the outer request was refused, so nothing was compared: ",40 sublist got];
  if[not `alice ~ got;
    '"a nested serveHttp clobbered the outer request's principal, leaving: ", -3!got];
  }]

/ ---- 11. a malformed principal header is a 400 that names the fault -------------------------------
/ Three different faults — unparseable, parseable but not an object, an object promote refuses — and each
/ must be ANSWERED (not signalled), with the trapped message passed through so the proxy operator can
/ tell them apart. The handler must never run and nothing may be left in effect.
.t.ran:0b;
.t.flagRan:{[x] .t.ran:1b; `ran};
.t.must400:{[json;fragment]
  .t.ran:0b;
  r:@[{[x] serveHttp[.t.flagRan; .t.req x]}; json; {[e] '"serveHttp signalled instead of answering 400: ",e}];
  if[not $[10h=type r; r like "HTTP/1.1 400 Bad Request*"; 0b]; '"expected 400 for ",json,", got: ",$[10h=type r; 60 sublist r; -3!r]];
  if[not count r ss fragment; '"400 body for ",json," did not say \"",fragment,"\": ",r];
  if[.t.ran; '"the handler ran under a refused principal header: ",json];
  if[not (::)~reqPrincipal; '"a refused header left a request principal behind"]; };

runTest[`malformedPrincipalHeaderIsA400ThatNamesTheFault; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and r~`kx.identity}];
  .t.must400["{\"sub\":\"alice\",";                       "not valid JSON"];
  .t.must400["42";                                       "a principal must be a dictionary"];
  .t.must400["[\"alice\"]";                              "a principal must be a dictionary"];
  .t.must400["{}";                                       "sub must be"];
  .t.must400["{\"sub\":[\"a\",\"b\"],\"groups\":[\"t\"]}"; "sub must be a non-null symbol atom"];
  .t.must400["{\"sub\":\"a\",\"groups\":[\"trader\",1]}";  "groups must be a symbol vector"];
  .t.must400["{\"sub\":\"a\",\"groups\":{\"x\":true}}";   "groups must be a symbol vector"];
  .t.must400["{\"sub\":\"a\",\"exp\":\"soon\"}";           "exp must be a numeric atom"];
  .t.must400["{\"sub\":\"a\",\"claims\":\"x\"}";           "claims must be a dictionary"];
  / and the refusal is a PROMOTION refusal, greppable as such by any client on either transport
  .t.must400["{\"sub\":\"a\",\"groups\":[1]}";             "kx.auth: malformed principal"];
  }]

/ The grant check comes FIRST: an asserter that may not assert learns nothing about how q parses headers.
runTest[`ungrantedProxySendingJunkGetsA403NotA400; {[]
  .t.resetHttp[];
  setPolicy[{[p;a;r] 0b}];
  .t.mustRefuse[{[] serveHttp[.t.echoPrincipal; .t.req "{\"sub\":[\"a\"]}"]}; "not permitted to assert"];
  }]

/ A well-formed header still asserts after all of the above — strictness refuses shapes, not principals.
runTest[`wellFormedHeaderStillAssertsAfterStrictness; {[]
  .t.resetHttp[];
  setLoginGroups[(enlist .t.u)!enlist `proxies];
  setPolicy[{[p;a;r] (a~`assert) and r~`kx.identity}];
  r:serveHttp[.t.echoPrincipal; .t.req "{\"sub\":\"alice\",\"groups\":[],\"iss\":\"http://idp\",\"exp\":1893456000}"];
  if[not `alice ~ r; '"the Lua-shaped header (empty groups, string iss, integer exp) was refused: ",-3!r];
  }]
