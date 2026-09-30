/ tests/login-space.q — the login->groups map, the subject rule, and the two invariants that keep
/ login-space honest.
/ .
/ A kdb+ login carries no IdP groups, which is the only reason "who may assert" ever needed a grant
/ table keyed on the subject rather than on groups. setLoginGroups closes that gap in the IDENTITY
/ layer, so every grant is group-keyed and there is one grant schema instead of two.
/ .
/ The subject rule: a connection's subject is the bound principal if one is bound, else the caller's
/ own login. That AMENDS the original contract, under which an unbound handle failed outright — so both
/ halves are pinned here: a mapped login resolves, and an unmapped login still denies.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ Restore the login map alongside the usual reset. Deliberately separate from .t.reset (which lives in
/ test.q and is shared): a check that maps a login must not leak that mapping into a later one.
.t.resetLogins:{[] logins::(`symbol$())!(); .t.reset[]; };

/ ---- 1. the map itself: shape, merging, and the atom-vs-vector trap -------------------------------
/ A map whose every value is a single symbol has a UNIFORM TYPED (11h) value list, so an unguarded
/ lookup yields an ATOM there and a vector in a mixed map. loginGroups must hide that difference —
/ callers key on `groups being a vector.
runTest[`loginGroupsAlwaysReturnsAVector; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist `solo)!enlist `superUsers];              / uniform 11h value list
  g:loginGroups `solo;
  if[not 11h = type g; '"a single-symbol mapping did not yield a symbol VECTOR, got type ",string type g];
  setLoginGroups[(enlist `multi)!enlist `viewer`trader];          / now the value list is general
  if[not 11h = type loginGroups `multi; '"a multi-group mapping did not yield a symbol vector"];
  if[not 11h = type loginGroups `solo; '"the earlier single-symbol mapping regressed after a merge"];
  }]

/ Partial updates merge rather than replace, so a host may declare logins in several calls.
runTest[`setLoginGroupsMerges; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist `a)!enlist `groupA];
  setLoginGroups[(enlist `b)!enlist `groupB];
  if[not `groupA ~ first loginGroups `a; '"the first mapping was lost by the second call"];
  if[not `groupB ~ first loginGroups `b; '"the second mapping did not land"];
  }]

/ An UNMAPPED login resolves to empty groups — the whole reason default-deny survives this feature.
runTest[`unmappedLoginHasNoGroups; {[]
  .t.resetLogins[];
  if[count loginGroups `nobody; '"an unmapped login was given groups"];
  if[not 11h = type loginGroups `nobody; '"an unmapped login did not yield an empty symbol vector"];
  }]

runTest[`setLoginGroupsRejectsNonSymbolValues; {[]
  .t.resetLogins[];
  .t.mustSignal[{[] setLoginGroups[(enlist `x)!enlist "notASymbol"]}; "must be a symbol"];
  .t.mustSignal[{[] setLoginGroups[enlist `notADict]}; "expects a dict"];
  }]

runTest[`setLoginGroupsRejectsInvalidKeys; {[]
  .t.resetLogins[];
  .t.mustSignal[{[] setLoginGroups[(enlist "login")!enlist `operators]}; "keys must be login symbols"];
  .t.mustSignal[{[] setLoginGroups[(enlist `)!enlist `operators]}; "must not be null"];
  }]

/ ---- 2. the subject rule, both halves ------------------------------------------------------------
/ A MAPPED login resolves: with no principal bound, the caller's own login decides, and a grant keyed
/ on the group its login carries is honoured.
runTest[`mappedLoginResolvesAsSubject; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist .t.u)!enlist `operators];
  setPolicy[{[p;a;r] (`operators in p`groups) and (a~`read) and r~`data.trades}];
  if[not `operators in (authorize[`read;`data.trades])`groups;
    '"a mapped login did not resolve as the subject with nothing bound"];
  }]

/ An UNMAPPED login still denies. This is the half that makes the amendment safe: the fallback subject
/ is only ever the caller's own login, and it is default-deny until somebody maps it.
runTest[`unmappedLoginStillDenies; {[]
  .t.resetLogins[];
  setPolicy[{[p;a;r] (`operators in p`groups) and (a~`read) and r~`data.trades}];
  .t.mustDeny[{[] authorize[`read;`data.trades]}];
  }]

/ The fallback principal carries `iss so provenance is readable for AUDIT — the one legitimate use.
runTest[`loginPrincipalCarriesLocalIssuer; {[]
  .t.resetLogins[];
  p:loginPrincipal .t.u;
  if[not `kdb.local ~ p`iss; '"a login-derived principal did not carry iss=`kdb.local"];
  if[not .t.u ~ p`sub; '"a login-derived principal did not carry its login as `sub"];
  }]

/ ---- 3. login and asserted principals decide identically ------------------------------------------
/ A login-derived principal goes through the identical promote[], and NOTHING downstream may branch on
/ how it arrived. Pin it by driving the same groups down both paths and demanding identical answers
/ from every decision verb. A future $[ on provenance inside a decision path fails HERE rather than
/ passing review.
runTest[`loginSpaceDecidesIdenticallyToTokenSpace; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist .t.u)!enlist `trader];
  / a policy that reads ONLY the promoted `groups — the shape every policy is supposed to have
  setPolicy[{[p;a;r] $[a~`assert; 1b; (`trader in p`groups) and a~`read]}];

  / login-space: nothing bound, so current[] falls back to the caller's login
  loginAnswers:(valid[]; (require[])`groups; (authorize[`read;`data.trades])`groups; entitled[`read;`data.trades`data.instruments]);

  / token-space: the same groups, arriving by assertion instead
  bind[`sub`groups!(`someuser; enlist `trader)];
  tokenAnswers:(valid[]; (require[])`groups; (authorize[`read;`data.trades])`groups; entitled[`read;`data.trades`data.instruments]);

  if[not loginAnswers ~ tokenAnswers;
    '"a decision differed by principal PROVENANCE — login-space has become a special path: ",
      (-3!loginAnswers)," vs ",-3!tokenAnswers];
  }]

/ Provenance is the ONLY thing that differs, and only in the audit field.
runTest[`onlyIssDistinguishesLoginFromToken; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist .t.u)!enlist `trader];
  .t.allowAll[];
  fromLogin:current[];
  bind[`sub`groups!(.t.u; enlist `trader)];
  fromToken:current[];
  / `~`, not `<>` — comparing two symbol VECTORS elementwise yields a boolean vector, and `if` on a
  / 1-item boolean vector 'type's rather than testing it.
  if[not fromLogin[`groups] ~ fromToken`groups; '"the two paths promoted `groups differently"];
  if[`iss in key fromToken; '"an asserted principal with no iss claim acquired one"];
  if[not `kdb.local ~ fromLogin`iss; '"the login path lost its audit issuer"];
  }]

/ ---- 4. asserted and direct principals share the authorization path --------------------------------
runTest[`assertedGroupsConferAdministration; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist .t.u)!enlist `superUsers];      / the asserter's login: may assert, NOT administer
  setPolicy[{[p;a;r]
    $[(a~`assert) and r~`kx.identity; `superUsers in p`groups;
      (a~`admin) and r~`kx.rbac;      `policyAdmins in p`groups;
      0b]}];
  bind[`sub`groups!(`escalator; enlist `policyAdmins)];
  if[not `escalator ~ (current[])`sub; '"the administrator-group principal was not bound"];
  if[not `escalator ~ (authorize[`admin; `kx.rbac])`sub;
    '"the asserted administrator was not authorized"];
  }]

/ A total wildcard must not prevent its holders from establishing a session.
runTest[`wildcardGrantDoesNotBlockAssertion; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist .t.u)!enlist `superUsers];
  setPolicy[{[p;a;r] $[(a~`assert) and r~`kx.identity; `superUsers in p`groups; `admins in p`groups]}];
  bind[`sub`groups!(`realAdmin; enlist `admins)];        / `admins holds :  -> everything, incl. admin:kx.rbac
  if[not `realAdmin ~ (current[])`sub;
    '"a principal in a wildcard-granted group could not bind — an operator's real administrators would be locked out of their own sessions"];
  if[not `admins in (authorize[`read;`data.trades])`groups; '"the wildcard grant did not decide"];
  }]

/ A literal allow-all policy must permit assertion.
runTest[`allowAllPolicyStillPermitsAssertion; {[]
  .t.resetLogins[];
  setPolicy[{[p;a;r] 1b}];
  bind[`sub`groups!(`anyone; enlist `anything)];
  if[not `anyone ~ (current[])`sub; '"an allow-all policy refused a bind"];
  }]

/ ---- 5. the login principal is promote's fixed point ----------------------------------------------
/ loginPrincipal is built canonical rather than promoted (every part already has the shape promote
/ produces), so it must be exactly what promote would have returned — otherwise login-space has quietly
/ become a second shaping site. Checked for a mapped login, an unmapped one, and the anonymous case.
runTest[`loginPrincipalIsAFixedPointOfPromote; {[]
  .t.resetLogins[];
  setLoginGroups[(enlist `solo)!enlist `superUsers];
  {[u] p:loginPrincipal u;
    if[not p ~ promote p; '"promote changed a login principal for ",(-3!u),": ",(-3!p)," -> ",-3!promote p]} each `solo`nobody;
  a:loginPrincipal `;
  if[not (type each a) ~ type each loginPrincipal `solo; '"the anonymous login principal has a different shape"];
  }]

/ A client that sent no credentials has `.z.u` null. That is not a malformed principal — it is nobody —
/ so the login fallback DECIDES (as a groupless subject) rather than signalling out of every verb.
runTest[`anonymousLoginDecidesAsNobodyRatherThanSignalling; {[]
  .t.resetLogins[];
  setPolicy[{[p;a;r] `operators in p`groups}];
  if[allows[loginPrincipal `;`assert;`kx.identity]; '"an anonymous login was allowed to assert"];
  if[allows[loginPrincipal `;`read;`data.trades]; '"an anonymous login was allowed data"];
  }]
