/ tests/rebind.q — per-handle replacement and principal-shape normalization.
/ .
/ A re-bind must replace the complete principal so stale fields cannot survive. The store must also accept
/ different principal shapes on independent handles. The demo covers the same behavior over real qIPC.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.

/ ---- 1. a narrower re-bind drops the stale field --------------------------------------------------
runTest[`narrowerRebindDropsStaleField; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`groups`tenant!(`alice;`x`y;`acme)];
  if[not `acme ~ (current[])`tenant; '"precondition failed: tenant was never bound"];
  bind[`sub`groups!(`bob;`z`w)];
  if[`tenant in key current[]; '"a stale tenant survived a narrower re-bind"];
  }]

/ ---- 2. a re-bind is an EXACT replacement, not a merge --------------------------------------------
runTest[`rebindIsExactReplacement; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`groups`exp`act!(`alice;`x`y;1893456000;(enlist `sub)!enlist "svc")];
  bind[`sub`groups!(`bob;`z`w)];
  survived:`sub`groups`tenant`exp`act inter key current[];
  if[not survived ~ `sub`groups; '"expected only sub+groups to survive, got: ", -3!survived];
  }]

/ ---- 3. a stale principal cannot outlive a re-bind INTO A POLICY DECISION -------------------------
/ The security consequence of 1: a tenant-scoped policy must not authorise bob on alice's tenant.
runTest[`staleTenantCannotReachPolicy; {[]
  .t.reset[];
  setPolicy[{[p;a;r] $[a~`assert; 1b; (r~`trades) and `acme~p`tenant]}];
  bind[`sub`tenant!(`alice;`acme)];
  if[not `acme ~ (authorize[`read;`trades])`tenant; '"precondition failed: alice was not allowed"];
  bind[(enlist `sub)!enlist `bob];                / a refreshed token, with no tenant claim at all
  .t.mustDeny[{[] authorize[`read;`trades]}];     / bob must NOT inherit acme
  }]

/ ---- 4. the structural invariant that makes a column-wise upsert impossible -----------------------
/ `bound`'s value list must stay a GENERAL list (0h). The moment its values are bare conforming dicts
/ it is a keyed table and the store-join acquires column semantics — the root cause of 1-3. Asserted
/ against the module's own store after a real bind, so it pins the representation, not a local copy.
runTest[`boundStoreValueListStaysGeneral; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`groups`tenant!(`alice;`x`y;`acme)];
  if[not 0h = type value bound; '"bound's value list is not general (type ", (string type value bound), "h)"];
  }]

/ ---- 5. a narrower bind is unaffected by ANOTHER handle holding a wider principal -----------------
/ In-process .z.w is fixed, so the second handle is seeded by cloning the module's OWN stored value
/ (no test-local copy of the store shape) onto a spare handle. Pre-fix this either 'mismatch'ed or
/ merged.
runTest[`narrowerBindUnaffectedBySecondHandle; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`groups`tenant!(`alice;`x`y;`acme)];   / handle 0 -> wide
  bound::bound,(enlist 9i)!enlist bound .z.w;     / spare handle 9i also holds the wide principal
  bind[`sub`groups!(`bob;`z`w)];                  / narrower re-bind: must neither signal nor merge
  if[not `bob ~ (current[])`sub; '"the narrower re-bind did not take effect"];
  if[`tenant in key current[]; '"the other handle's tenant merged into this one"];
  }]

/ ---- 5b. bind[()!()] on the ALLOW path is REFUSED: a principal with no identity does not bind ---------
/ assertion-gate.q's unsetPolicyRefusesBind / grantToOtherLoginRefusesBind use ()!() only as an inert
/ payload — the gate refuses before promote ever runs. Here it reaches promote, which derives no `sub from
/ a dict with neither `sub, `claims.sub nor `client, and refuses by name rather than binding a subject
/ that is an empty symbol vector (which is what it used to do).
runTest[`emptyPrincipalIsRefused; {[]
  .t.reset[]; .t.allowAll[];
  .t.mustSignal[{[] bind[()!()]}; "malformed principal"];
  .t.mustSignal[{[] bind[()!()]}; "sub must be"];
  if[.z.w in key bound; '"a refused bind still stored something on the handle"];
  }]

/ ---- 5c. the shape contract: one refusal per malformed field, named, after the coercions -----------
/ promote is the single canonicalisation authority, so what it cannot coerce it must REFUSE — otherwise
/ the junk crashes the first ordinary decision (`x in p`groups`, valid[]'s exp compare, denialText's
/ string[sub]) far from the boundary that let it in. Each case is the q value .j.k or PyKX would actually
/ produce for the JSON shape named in the comment.
.t.refuses:{[p;what]
  e:@[promote; p; {x}];
  if[not 10h=type e; '"expected promote to refuse ",(-3!p),", got: ",-3!e];
  if[not e like "kx.auth: malformed principal*"; '"a refusal must be named as one, got: ",e];
  if[not count e ss what; '"refused for the wrong reason — wanted \"",what,"\", got: ",e]; };

runTest[`promoteRefusesEachMalformedShapeByName; {[]
  .t.reset[];
  .t.refuses[.j.k "{\"sub\":[\"a\",\"b\"],\"groups\":[\"t\"]}";      "sub must be a non-null symbol atom, got 0h"];
  .t.refuses[.j.k "{\"sub\":42}";                                "sub must be a non-null symbol atom, got -9h"];
  .t.refuses[.j.k "{\"sub\":null,\"groups\":[\"t\"]}";           "sub must be"];
  .t.refuses[.j.k "{\"groups\":[\"t\"]}";                        "sub must be"];          / no identity at all
  .t.refuses[`sub`client!(`;`);                                     "got a null symbol"];    / PyKX: both absent
  .t.refuses[.j.k "{\"sub\":\"a\",\"groups\":[1,2]}";            "groups must be a symbol vector, got 9h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"groups\":[\"trader\",1]}";   "groups must be a symbol vector, got 0h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"groups\":{\"x\":1}}";        "groups must be a symbol vector, got 99h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"aud\":[1]}";                 "aud must be a symbol vector"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"scopes\":[\"x\",2]}";        "scopes must be a symbol vector"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"exp\":\"soon\"}";            "exp must be a numeric atom of unix seconds, got 10h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"exp\":[1,2]}";               "exp must be a numeric atom of unix seconds, got 9h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"exp\":true}";                "exp must be a numeric atom of unix seconds, got -1h"];
  .t.refuses[`sub`exp!(`a;`soon);                                   "exp must be a numeric atom of unix seconds, got -11h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"claims\":\"notadict\"}";     "claims must be a dictionary, got 10h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"claims\":null}";             "claims must be a dictionary"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"tenant\":[\"x\"]}";          "tenant must be a symbol atom, got 0h"];
  .t.refuses[.j.k "{\"sub\":\"a\",\"iss\":7}";                   "iss must be a symbol atom, got -9h"];
  .t.refuses[`sub`client!(`a;1 2);                                  "client must be a symbol atom, got 7h"];
  / not a dictionary at all — what .j.k yields for a JSON number, array, string or null
  .t.refuses[.j.k "42";                                             "a principal must be a dictionary"];
  .t.refuses[.j.k "[1,2]";                                          "a principal must be a dictionary"];
  .t.refuses[.j.k "null";                                           "a principal must be a dictionary"];
  .t.refuses[([k:`a`b] v:1 2);                                      "keyed table"];
  .t.refuses[`sub`sub!(`a;`b);                                      "duplicate keys"];
  }]

/ The refusal is the FIRST fault only, so one message names one field: a caller fixes them one at a time
/ and never has to parse a list.
runTest[`promoteNamesOneFieldPerRefusal; {[]
  .t.reset[];
  e:@[promote; .j.k "{\"sub\":[\"a\"],\"groups\":[1],\"exp\":\"x\"}"; {x}];
  if[not count e ss "sub must be"; '"the first fault was not the one named: ",e];
  if[any count each e ss/: ("groups must be";"exp must be"); '"more than one field was named: ",e];
  }]

/ Strictness is a check AFTER coercion, never instead of it: everything promote coerced before, it must
/ still coerce, and everything it left alone it must still leave alone.
runTest[`promoteStillCoercesWhatItAlwaysDid; {[]
  .t.reset[];
  p:promote .j.k "{\"sub\":\"alice\",\"groups\":[\"trader\",\"viewer\"],\"iss\":\"http://idp\",\"exp\":1893456000,\"act\":{\"sub\":\"svc\"},\"foo\":[1,2]}";
  if[not `alice ~ p`sub;              '"a string sub was not symbolised"];
  if[not `trader`viewer ~ p`groups;   '"a JSON string array was not widened to a symbol vector"];
  if[not -11h=type p`iss;             '"a string iss was not symbolised"];
  if[not -12h=type p`exp;             '"a float exp was not canonicalised to a timestamp"];
  if[not ((enlist `sub)!enlist "svc") ~ p`act; '"act was touched — the module never reads it"];
  if[not 1 2f ~ p`foo;                '"an unknown key was touched"];
  if[not (`symbol$()) ~ (promote .j.k "{\"sub\":\"a\",\"groups\":[]}")`groups; '"an empty groups array did not become an empty symbol vector"];
  if[not (enlist `trader) ~ (promote .j.k "{\"sub\":\"a\",\"groups\":\"trader\"}")`groups; '"a scalar string groups was not widened"];
  if[not (enlist `t) ~ (promote `sub`groups!(`a;`t))`groups; '"a scalar symbol groups was not widened"];
  if[not `openid`profile ~ (promote `sub`scopes!(`a;("openid";"profile")))`scopes; '"a list of strings was not symbolised"];
  if[not `acme ~ (promote `sub`tenant!(`a;"acme"))`tenant; '"a string tenant was not symbolised"];
  if[not (`$"alice-uuid") ~ (promote `client`claims!(`kxmcp;(enlist `sub)!enlist "alice-uuid"))`sub; '"sub was not derived from claims.sub"];
  if[not `kxmcp ~ (promote `sub`client!(`;`kxmcp))`sub; '"a null sub was not derived from client"];
  if[not -5h=type (promote `sub`exp!(`a;32000h))`exp; '"a short exp must still be left unconverted (and deny), not refused"];
  if[not 0Np ~ (promote .j.k "{\"sub\":\"a\",\"exp\":null}")`exp; '"a null exp must still canonicalise to a null timestamp (and deny)"];
  }]

/ promote on its own output is the identity, so a promoted principal — a --promoted-out file, a re-bind of
/ current[] — is never refused for carrying the timestamp promote itself put there.
runTest[`promoteIsIdempotentOnItsOwnOutput; {[]
  .t.reset[];
  p:`sub`groups`exp`client`scopes`claims!(`a;("x";"y");1893456000;"kxmcp";"openid";(enlist `tenant)!enlist "acme");
  if[not (promote promote p) ~ promote p; '"promote is not idempotent: ",(-3!promote p)," vs ",-3!promote promote p];
  if[not -12h=type (promote `sub`exp!(`a;2030.01.01D0))`exp; '"a timestamp exp was not accepted as already canonical"];
  }]

/ A refused re-bind is a refused bind: nothing is stored, and the principal already on the handle stays.
runTest[`refusedRebindLeavesThePriorPrincipalInEffect; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`groups!(`alice; enlist `trader)];
  .t.mustSignal[{[] bind[`sub`groups!(`mallory; 1 2 3)]}; "groups must be a symbol vector"];
  if[not `alice ~ (current[])`sub; '"a refused re-bind disturbed the principal in effect: ",-3!current[]];
  }]

/ ---- 6-9. promote[]/bind[] accept a UNIFORM-typed principal (previously 'type) --------------------
/ An all-atoms dict has a typed value list; promoting must widen it rather than fail.
runTest[`uniformTypedPrincipalBinds; {[]
  .t.reset[]; .t.allowAll[];
  bind[(enlist `sub)!enlist `bob];
  if[not `bob ~ (current[])`sub; '"a single-key principal did not bind"];
  }]

runTest[`promoteWidensUniformSymbolDict; {[]
  if[not `a ~ (promote `sub`iss!(`a;`b))`sub; '"promote mangled an all-atoms principal"];
  }]

runTest[`promoteSymbolisesScalarAud; {[]
  if[not (enlist `kxmcp) ~ (promote `sub`aud!(`carol;`kxmcp))`aud; '"scalar aud not widened to a vector"];
  }]

runTest[`promoteSymbolisesScalarScopes; {[]
  if[not (enlist `openid) ~ (promote `sub`scopes!(`carol;`openid))`scopes; '"scalar scopes not widened"];
  }]

/ ---- 10. promotion itself is unchanged: claims-sourced groups + exp canon still hold --------------
/ .t.reset[] restores the default claim paths, so the setClaims below cannot leak into a later check.
runTest[`claimsSourcedGroupsAndExpCanon; {[]
  .t.reset[]; .t.allowAll[];
  setClaims[(enlist `groups)!enlist "realm_access.roles"];
  cl:(`realm_access`sub)!(((enlist `roles)!enlist ("trader";"viewer"));"alice-uuid");
  bind[`sub`client`scopes`claims`exp!(`$"alice-uuid";`kxmcp;("openid";"profile");cl;1893456000)];
  p:current[];
  if[not `trader`viewer ~ p`groups; '"groups not extracted from the configured claim path"];
  if[not -12h = type p`exp;         '"exp not canonicalised to a timestamp"];
  if[not valid[];                   '"a far-future exp was treated as expired"];
  if[not `openid`profile ~ p`scopes; '"scopes not promoted to symbols"];
  }]

/ ---- 11. clear[] still fully resets a handle (the disconnect path) --------------------------------
/ clear[] drops the handle's BINDING. It no longer leaves current[] at the unbound sentinel, because
/ the subject rule falls back to the caller's own login — so what clear guarantees is that the asserted
/ principal is gone and the connection has dropped back to deciding as itself, which is what the
/ .z.po/.z.pc wiring needs in order to stop handle-id reuse carrying an identity across connections.
runTest[`clearResetsHandle; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`tenant!(`alice;`acme)];
  clear .z.w;
  if[.z.w in key bound; '"clear left an entry in the per-handle store"];
  if[`alice ~ (current[])`sub; '"clear left the asserted principal in effect"];
  if[not .z.u ~ (current[])`sub; '"after clear the subject is not the caller's own login"];
  }]

/ ---- 12. promote[] group precedence: a direct `groups wins outright, then the claim search order ----
/ .t.reset[] restores the default (empty) claimPaths`groups, so both fallback cases below reach
/ extractGroups's built-in search order rather than a configured path. `client` is included throughout
/ so the unrelated sub-derivation fallback never has to fall through to a missing key.
runTest[`promoteGroupsPrecedenceAndFallbackOrder; {[]
  .t.reset[];
  everyone:(enlist `groups)!enlist "everyone";
  direct:promote `groups`client`claims!(`admin`ops;`kxmcp;everyone);
  if[not `admin`ops ~ direct`groups; '"a direct groups value did not take precedence over claims"];
  realmAccess:(enlist `roles)!enlist ("trader";"viewer");
  claimsWithRealmAccess:(enlist `realm_access)!enlist realmAccess;
  viaRealmAccess:promote `client`claims!(`kxmcp;claimsWithRealmAccess);
  if[not `trader`viewer ~ viaRealmAccess`groups; '"realm_access.roles was not reached when groups was absent"];
  claimsWithRolesOnly:(enlist `roles)!enlist ("ops";"support");
  viaRoles:promote `client`claims!(`kxmcp;claimsWithRolesOnly);
  if[not `ops`support ~ viaRoles`groups; '"roles was not reached as the final fallback"];
  / when BOTH resolve, realm_access.roles (earlier in the search order) must win over roles — the two
  / cases above each supply only one candidate, so neither can catch the search trying them out of order
  claimsWithBoth:`realm_access`roles!(realmAccess;("ops";"support"));
  viaBoth:promote `client`claims!(`kxmcp;claimsWithBoth);
  if[not `trader`viewer ~ viaBoth`groups; '"realm_access.roles did not win over roles when both resolve"];
  }]

/ ---- 13. promote[] derives sub/tenant from claims, and symbolises a claimed iss ---------------------
runTest[`promoteDerivesSubTenantAndIss; {[]
  .t.reset[];
  subFromClaims:promote `client`claims!(`kxmcp;(enlist `sub)!enlist "alice-uuid");
  if[not (`$"alice-uuid") ~ subFromClaims`sub; '"sub was not derived from claims.sub"];
  subFromClient:promote (enlist `client)!enlist `kxmcp;
  if[not `kxmcp ~ subFromClient`sub; '"sub was not derived from client when neither sub nor claims.sub exist"];
  tenantFromClaims:promote `sub`claims!(`carol;(enlist `tenant)!enlist "acme");
  if[not `acme ~ tenantFromClaims`tenant; '"tenant was not derived from claims.tenant"];
  issSymbolised:promote `sub`iss!(`carol;"https://idp.example/realms/kx");
  if[not -11h = type issSymbolised`iss; '"a claimed iss was not symbolised"];
  }]

/ ---- 14. valid[] on principal expiry --------------------------------------------------------------
/ No clock-mocking needed: valid[] is a plain comparison against .z.p, so an already-past exp is enough.
runTest[`validIsTrueWithNoExpKey; {[]
  .t.reset[]; .t.allowAll[];
  bind[(enlist `sub)!enlist `noexp];
  if[not .z.w in key bound; '"precondition failed: nothing bound"];
  if[not valid[]; '"a principal with no exp key was treated as expired"];
  }]

runTest[`validIsFalseForAnExpiredPrincipal; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`exp!(`stale;1000000000)];               / 2001-09-09, well past .z.p; also exercises canon's -7h branch
  if[valid[]; '"an already-expired principal was treated as valid"];
  }]

/ canon's OTHER accepted type — -9h float — was never exercised; every existing exp test uses a long
/ literal, which types as -7h. A float is what .j.k actually produces from JSON, so the HTTP path is
/ this branch's natural producer.
runTest[`canonConvertsAFloatTypedExp; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`exp!(`floaty;1893456000f)];
  p:current[];
  if[not -12h=type p`exp;
    '"expected canon to convert a float-typed exp to a timestamp, got type ",string type p`exp];
  if[not valid[]; '"expected a future float-typed exp to still be valid"];
  }]

/ Every numeric atom wide enough to hold an epoch must canonicalise — not just the long PyKX produces
/ and the float .j.k produces. An int exp used to fall through unconverted and then compare raw
/ against .z.p, whose unit is nanoseconds since 2000, so a 2030 expiry read as 2000.01.01D00:00:01.893
/ and DENIED a principal that should have been valid. `valid[]` is the assertion that matters; the type
/ is only how it broke.
runTest[`canonConvertsEveryEpochWideNumericExp; {[]
  {[e]
    .t.reset[]; .t.allowAll[];
    bind[`sub`exp!(`numy;e)];
    if[not -12h=type current[]`exp;
      '"canon left an exp of type ",(string type e)," unconverted"];
    if[not valid[]; '"a future exp of type ",(string type e)," was treated as expired"];
    } each (1893456000i;1893456000;1893456000e;1893456000f);
  }]

/ The complement: a short cannot hold any realistic epoch (max 32767), so canon deliberately does not
/ convert one. It must still DENY rather than crash — the safe half of the old behaviour, kept.
runTest[`canonLeavesATooNarrowExpUnconvertedAndDenies; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`exp!(`shorty;32000h)];
  if[not -5h=type current[]`exp; '"expected a short exp to be left unconverted"];
  if[valid[]; '"a short exp cannot be a real epoch and must not read as valid"];
  }]

/ ---- 15. require[] signals on an expired principal ------------------------------------------------
runTest[`requireSignalsOnAnExpiredPrincipal; {[]
  .t.reset[]; .t.allowAll[];
  bind[`sub`exp!(`stale;1000000000)];
  .t.mustSignal[{[] require[]}; "expired"];
  }]

/ ---- 16. setClaims[] rejects a non-dict argument ---------------------------------------------------
runTest[`setClaimsRejectsNonDictInput; {[]
  .t.reset[];
  .t.mustSignal[{[] setClaims[enlist `notADict]}; "setClaims: expects a dict"];
  }]

/ ---- 17. setClaims[] coerces symbol paths to strings ---------------------------------------------
/ A symbol path used to be stored as given, and then every bind signalled a bare 'type in `dig`.
runTest[`setClaimsCoercesSymbolPaths; {[]
  .t.reset[]; .t.allowAll[];
  setClaims[`groups`tenant!(`realm_access.roles;`org.tenant)];
  if[not all 10h = type each claimPaths`groups`tenant; '"symbol paths were not stored as strings"];
  if[not ("realm_access.roles";"org.tenant") ~ claimPaths`groups`tenant; '"coerced paths lost their text"];
  cl:`sub`realm_access`org!("alice-uuid";(enlist `roles)!enlist ("trader";"viewer");(enlist `tenant)!enlist "acme");
  bind[`sub`claims!(`$"alice-uuid";cl)];
  p:current[];
  if[not `trader`viewer ~ p`groups; '"groups not promoted through a symbol-configured path"];
  if[not `acme ~ p`tenant;          '"tenant not promoted through a symbol-configured path"];
  }]

/ ---- 18. setClaims[] refuses a path of any other type, by name, and merges nothing -------------
runTest[`setClaimsRejectsNonPathValues; {[]
  .t.reset[];
  before:claimPaths;
  .t.mustSignal[{[] setClaims[`groups`tenant!("realm_access.roles";42)]}; "the path for tenant must be a string or a symbol"];
  .t.mustSignal[{[] setClaims[(enlist `groups)!enlist `a`b]}; "the path for groups must be a string or a symbol"];
  .t.mustSignal[{[] setClaims[`groups`tenant!"ab"]}; "the path for groups must be a string or a symbol"];
  if[not before ~ claimPaths; '"a refused setClaims merged part of its argument"];
  }]
