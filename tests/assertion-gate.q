/ tests/assertion-gate.q — the kx.auth identity-assertion gate: bind[] asks the same authorization
/ policy WHO may assert — an S/A/R decision keyed on the caller's login (.z.u, passed as `sub) with
/ action `assert on resource `kx.identity, default-deny (policy is deny-all until setPolicy). "Who may
/ assert" is a host grant in the one policy, not a module built-in.
/ .
/ This covers the module LOGIC; the live .z.u-over-IPC property (a real second connection under a
/ different login is refused at bind) is exercised by demos/local-assertion. In-process .z.u is fixed,
/ so we grant `assert to whatever .z.u is and prove caller-keying by also granting it to a DIFFERENT
/ login and confirming bind is then refused.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.

/ ---- 1. default-deny: policy unset (deny-all) -> bind refuses (a mere connection is not enough) ---
runTest[`unsetPolicyRefusesBind; {[]
  .t.reset[];
  setPolicy[{[p;a;r] 0b}];                        / the module's own default, stated explicitly
  .t.mustDeny[{[] bind[()!()]}];
  }]

/ ---- 2. a policy granting `assert on `kx.identity to THIS caller -> bind succeeds ---------------------
/ current[] must reflect the ASSERTED principal, whose `sub differs from the caller's — which is the
/ whole point: the caller is authorised to assert, it does not become the subject.
runTest[`grantedCallerBindsAssertedPrincipal; {[]
  .t.reset[];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and p[`sub]~.t.u}];
  bind[`sub`groups!(`enduser;`viewer`trader)];
  if[not `enduser ~ (current[])`sub; '"asserted principal not in effect after bind"];
  }]

/ ---- 3. grant `assert only to a DIFFERENT login -> bind refuses -----------------------------------
/ Proves the gate keys on the CALLER's .z.u, not on the asserted principal or the mere connection.
runTest[`grantToOtherLoginRefusesBind; {[]
  .t.reset[];
  setPolicy[{[p;a;r] (a~`assert) and (r~`kx.identity) and p[`sub]~`otheruser}];
  .t.mustDeny[{[] bind[()!()]}];
  }]

/ ---- 4. the data S/A/R path is unaffected: a granted resource returns the principal ---------------
runTest[`dataGrantAllowsGrantedResource; {[]
  .t.reset[];
  setPolicy[{[p;a;r] $[a~`assert; 1b; (a~`read) and (r~`trades) and `trader in p`groups]}];
  bind[`sub`groups!(`alice; enlist `trader)];     / enlist: mirror PyKX's 1-group vector shape
  if[not `trader in (authorize[`read;`trades])`groups; '"authorize did not return the principal"];
  }]

/ ---- 5. ... and an ungranted resource is denied (default-deny governs) ----------------------------
runTest[`dataGateDeniesUngrantedResource; {[]
  .t.reset[];
  setPolicy[{[p;a;r] $[a~`assert; 1b; (a~`read) and (r~`trades) and `trader in p`groups]}];
  bind[`sub`groups!(`alice; enlist `trader)];
  .t.mustDeny[{[] authorize[`read;`secrets]}];
  }]

/ ---- 6. configure[] rejects a malformed (user;password) pair -------------------------------------
/ Deliberately rejection-only: .t.reset[] does not restore svc (only bound/claimPaths), so testing the
/ ACCEPTED path here would leak a service credential pair into every later check in the run.
runTest[`configureRejectsMalformedInput; {[]
  .t.reset[];
  .t.mustSignal[{[] configure[enlist `onlyOneItem]}; "configure: expects"];
  .t.mustSignal[{[] configure[(`user;"pw";"extra")]}; "configure: expects"];
  }]
