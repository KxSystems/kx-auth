/ tests/declared.q — aimeta-declared authorization through the policy-independent kx.auth seam.
/ .
/ Loaded after both peer modules so protected calls can be exercised against the real RBAC policy.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

.t.resetDeclared:{[]
  .t.resetRbac[];
  nextProtectToken::0;
  protectedOriginals::();
  protectedWrappers::();
  declared::([] token:`long$(); name:`symbol$(); act:`symbol$(); res:`symbol$());
  };

.t.authMeta:{[names;actions;resources]
  ([] name:names; authorize:{[a;r] `action`resource!(string a;string r)}'[actions;resources]) };

runTest[`protectRejectsUnsupportedValuesAndArity; {[]
  .t.resetDeclared[];
  .t.mustSignal[{[] protect[+]}; "expects a q lambda"];
  .t.mustSignal[{[] protect {[a;b;c;d;e;f;g;h] a}}; "at most 7 arguments"];
  }]

runTest[`protectedFunctionDeniesBeforeAnnotationsLoad; {[]
  .t.resetDeclared[];
  .t.protectedPreload:protect {[x] x+1};
  if[not 104h=type .t.protectedPreload; '"protect did not return a projection"];
  .t.mustSignal[{[] .t.protectedPreload 41}; "no loaded @authorize requirement"];
  }]

/ The projection keeps every supported callable rank, including q's niladic projection convention.
runTest[`protectPreservesAritiesZeroThroughSeven; {[]
  .t.resetDeclared[];
  .t.p0:protect {[] 0};
  .t.p1:protect {[a] a};
  .t.p2:protect {[a;b] a+b};
  .t.p3:protect {[a;b;c] a+b+c};
  .t.p4:protect {[a;b;c;d] a+b+c+d};
  .t.p5:protect {[a;b;c;d;e] a+b+c+d+e};
  .t.p6:protect {[a;b;c;d;e;f] a+b+c+d+e+f};
  .t.p7:protect {[a;b;c;d;e;f;g] a+b+c+d+e+f+g};
  ns:`.t.p0`.t.p1`.t.p2`.t.p3`.t.p4`.t.p5`.t.p6`.t.p7;
  .t.metaSnapshot:.t.authMeta[ns;8#`read;8#`data.test];
  .aimeta.getFunctions:{[] .t.metaSnapshot};
  if[8<>loadAnnotations[]; '"loadAnnotations did not load every protected arity"];
  .t.installRbac[];
  grant[`tester;`read;`data.test];
  setLoginGroups[(enlist .t.u)!enlist `tester];
  got:(.t.p0[];.t.p1 1;.t.p2[1;2];.t.p3[1;2;3];.t.p4[1;2;3;4];
       .t.p5[1;2;3;4;5];.t.p6[1;2;3;4;5;6];.t.p7[1;2;3;4;5;6;7]);
  if[not 0 1 3 6 10 15 21 28~got; '"a protected projection changed its lambda's result: ",-3!got];
  }]

/ Declared enforcement belongs to the seam, not to the standard RBAC implementation behind it.
runTest[`protectedFunctionWorksWithANonRbacPolicy; {[]
  .t.resetDeclared[];
  .t.customPolicyProtected:protect {[x] x+1};
  .aimeta.getFunctions:{[] .t.authMeta[
    enlist `.t.customPolicyProtected;enlist `run;enlist `custom.policy]};
  loadAnnotations[];
  setPolicy {[p;a;r] (`run;`custom.policy)~(a;r)};
  if[42<>.t.customPolicyProtected 41; '"protect did not delegate through the custom policy"];
  }]

/ Tokens, not function values, key declarations: byte-identical bodies can carry different grants.
runTest[`identicalBodiesKeepDistinctDeclarations; {[]
  .t.resetDeclared[];
  .t.readIdentity:protect {[x] x};
  .t.execIdentity:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[
    `.t.readIdentity`.t.execIdentity;`read`exec;`data.test`analytic]};
  loadAnnotations[];
  .t.installRbac[];
  grant[`tester;`read;`data.test];
  setLoginGroups[(enlist .t.u)!enlist `tester];
  if[42<>.t.readIdentity 42; '"the read declaration did not authorize"];
  .t.mustDeny[{[] .t.execIdentity 42}];
  }]

runTest[`annotationLoadIsAtomicAndRequiresProtection; {[]
  .t.resetDeclared[];
  .t.atomicGood:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.atomicGood;enlist `read;enlist `data.test]};
  loadAnnotations[];
  before:declared;
  .t.atomicRaw:{[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[
    `.t.atomicGood`.t.atomicRaw;`read`read;`data.test`data.other]};
  .t.mustSignal[{[] loadAnnotations[]}; "is annotated but is not a .kx.auth.protect wrapper"];
  if[not before~declared; '"a failed annotation load changed the live snapshot"];
  }]

/ A live published protected binding may not silently lose its declaration during a refresh.
runTest[`protectedPublishedFunctionRequiresAnnotation; {[]
  .t.resetDeclared[];
  .t.stillAnnotated:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.stillAnnotated;enlist `read;enlist `data.test]};
  loadAnnotations[];
  before:declared;
  .t.missingAnnotation:protect {[x] x};
  .t.metaSnapshot:.t.authMeta[enlist `.t.stillAnnotated;enlist `read;enlist `data.test];
  .t.metaSnapshot:.t.metaSnapshot uj ([] name:enlist `.t.missingAnnotation; authorize:enlist ());
  .aimeta.getFunctions:{[] .t.metaSnapshot};
  .t.mustSignal[{[] loadAnnotations[]}; "have no @authorize declaration"];
  if[not before~declared; '"a missing declaration changed the live snapshot"];
  }]

runTest[`successfulEmptyLoadRevokesPriorDeclarations; {[]
  .t.resetDeclared[];
  .t.removedAnnotation:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.removedAnnotation;enlist `read;enlist `data.test]};
  loadAnnotations[];
  .t.removedWrapper:.t.removedAnnotation;
  .t.removedAnnotation:{[x] x};
  .aimeta.getFunctions:{[] ([] name:enlist `.t.removedAnnotation)};
  if[0<>loadAnnotations[]; '"an annotation-free metadata snapshot did not clear declarations"];
  .t.mustSignal[{[] .t.removedWrapper 1}; "no loaded @authorize requirement"];
  }]

runTest[`annotationRejectsEmptyResource; {[]
  .t.resetDeclared[];
  .t.emptyResource:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.emptyResource;enlist `read;enlist `]};
  .t.mustSignal[{[] loadAnnotations[]}; "malformed resource path"];
  }]

/ The wholly-null resource above is one way validDeclaredPath refuses; an internal or trailing EMPTY
/ segment is another, and had never been exercised on this side (kx.rbac's separate validPath IS
/ tested against these exact strings in tests/rbac.q, but that is a different function).
runTest[`annotationRejectsInternalAndTrailingEmptySegments; {[]
  .t.resetDeclared[];
  .t.internalEmpty:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.internalEmpty;enlist `read;enlist `$"data..test"]};
  .t.mustSignal[{[] loadAnnotations[]}; "malformed resource path"];
  .t.resetDeclared[];
  .t.trailingEmpty:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.trailingEmpty;enlist `read;enlist `$"data."]};
  .t.mustSignal[{[] loadAnnotations[]}; "malformed resource path"];
  }]

/ A row must carry BOTH `action and `resource keys, not merely be a dict. Hand-built rather than via
/ .t.authMeta, which always emits both.
runTest[`annotationRejectsMissingAuthorizeKey; {[]
  .t.resetDeclared[];
  .t.missingKey:protect {[x] x};
  .aimeta.getFunctions:{[] ([] name:enlist `.t.missingKey; authorize:enlist (enlist `action)!enlist "read")};
  .t.mustSignal[{[] loadAnnotations[]}; "malformed @authorize metadata"];
  }]

/ A symbol atom would pass silently (the string coercion is a no-op for it), so this needs a genuinely
/ non-string, non-symbol value to trip the check.
runTest[`annotationRejectsNonStringActionOrResource; {[]
  .t.resetDeclared[];
  .t.badType:protect {[x] x};
  .aimeta.getFunctions:{[] ([] name:enlist `.t.badType; authorize:enlist `action`resource!(42;"data.test"))};
  .t.mustSignal[{[] loadAnnotations[]}; "action and resource must be strings"];
  }]

/ The positive half of the comment above: a symbol atom is silently ACCEPTED, and the resulting
/ declaration enforces exactly as a string-typed one would.
runTest[`annotationAcceptsAnAlreadySymbolActionAndResource; {[]
  .t.resetDeclared[];
  .t.symbolTyped:protect {[x] x};
  .aimeta.getFunctions:{[] ([] name:enlist `.t.symbolTyped; authorize:enlist `action`resource!(`read;`data.test))};
  if[1<>loadAnnotations[]; '"a symbol-typed action/resource did not load"];
  setPolicy policySpec[];
  grant[`tester;`read;`data.test];
  setLoginGroups[(enlist .t.u)!enlist `tester];
  if[42<>.t.symbolTyped 42; '"the symbol-typed declaration did not authorize"];
  }]

/ The empty-action mirror of annotationRejectsEmptyResource above.
runTest[`annotationRejectsEmptyAction; {[]
  .t.resetDeclared[];
  .t.emptyAction:protect {[x] x};
  .aimeta.getFunctions:{[] .t.authMeta[enlist `.t.emptyAction;enlist `;enlist `data.test]};
  .t.mustSignal[{[] loadAnnotations[]}; "action must not be empty"];
  }]

runTest[`emptyGenericAimetaCollectionClearsDeclarations; {[]
  .t.resetDeclared[];
  .aimeta.getFunctions:{[] ()};
  if[0<>loadAnnotations[]; '"an empty generic aimeta collection did not clear declarations"];
  }]

/ The four aimeta-input-shape guards, none previously exercised: every other test in this file
/ assigns a working .aimeta.getFunctions before calling loadAnnotations, so none of unavailable /
/ throwing / malformed / missing-name-column was ever reached.
runTest[`loadAnnotationsRejectsMalformedAimetaInputs; {[]
  .t.resetDeclared[];
  / aimeta unavailable: no .aimeta.getFunctions defined at all. Every other test in this file leaves
  / a working getter behind, so it must be removed rather than merely overwritten.
  @[{![`.aimeta;();0b;enlist `getFunctions]};(::);{[e]}];
  .t.mustSignal[{[] loadAnnotations[]}; "aimeta is unavailable"];
  / the getter itself throws.
  .aimeta.getFunctions:{[] '"boom"};
  .t.mustSignal[{[] loadAnnotations[]}; "cannot read aimeta functions"];
  / a non-empty, non-table return.
  .aimeta.getFunctions:{[] 42};
  .t.mustSignal[{[] loadAnnotations[]}; "malformed function collection"];
  / a table missing the required `name column.
  .aimeta.getFunctions:{[] ([] foo:enlist 1)};
  .t.mustSignal[{[] loadAnnotations[]}; "has no name column"];
  }]

/ Two more guards, likewise never exercised despite existing since the older cross-reference audit
/ named both as GAPs there.
runTest[`loadAnnotationsRejectsDuplicateNamesAndTokens; {[]
  / duplicate NAME: two rows in the aimeta table naming the same wrapper twice.
  .t.resetDeclared[];
  .t.dupName:protect {[x] x};
  .aimeta.getFunctions:{[] ([] name:`.t.dupName`.t.dupName;
    authorize:2#enlist `action`resource!("read";"data.test"))};
  .t.mustSignal[{[] loadAnnotations[]}; "duplicate annotated function name"];
  / duplicate TOKEN: two distinct names that both resolve to the SAME wrapper value.
  .t.resetDeclared[];
  .t.aliasA:protect {[x] x};
  .t.aliasB:.t.aliasA;
  .aimeta.getFunctions:{[] .t.authMeta[`.t.aliasA`.t.aliasB;`read`read;`data.test`data.test]};
  .t.mustSignal[{[] loadAnnotations[]}; "two annotations resolve to one protected function"];
  }]
