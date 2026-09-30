/ tests/bench.q — the performance exit criterion, measured rather than asserted in prose.
/ .
/ The scalar decision is consulted on every protected operation and must stay in the low microseconds.
/ .
/ Thresholds are deliberately loose — this runs in CI on unknown hardware, and the point is to catch a
/ REGRESSION IN COMPLEXITY (a memo that stopped working, a scan that crept back onto the per-resource
/ path), not to police microseconds. A generous bound that fails loudly beats a tight one that flaps.
/ .
/ Loaded by tests/test.q, which owns the driver, the module load and the .t. helpers.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ Wall-clock milliseconds for n repetitions of a niladic lambda.
.t.ms:{[n;f] t:.z.p; do[n; f[]]; `long$(.z.p-t)%1000000};

/ Microseconds per call.
.t.us:{[n;f] (.t.ms[n;f]*1000)%n};

/ A grant table with `rows` rows spread over many groups and a deep resource tree, so a scan of it is
/ measurably more expensive than a memo hit. Includes the rows the subject under test actually holds.
.t.bigGrants:{[rows]
  n:rows-2;
  t:([] grp:`$"grp",/:string til n;
        act:n#`read`write`delete`query;
        res:`$"data.area",/:(string til n),\:".tbl");
  t upsert ([] grp:`benchGroup`benchGroup; act:`read`write; res:`data.bench`data.bench) };

.t.benchSubject:`sub`groups!(`benchUser; enlist `benchGroup);

/ ---- 1. a single decision is in the low microseconds -----------------------------------------------
runTest[`benchSingleDecisionIsMicroseconds; {[]
  .t.resetRbac[];
  setGrants[.t.bigGrants 1000];
  p:.t.benchSubject;
  decide[p;`read;`data.bench];                     / warm the memo
  us:.t.us[20000; {[] decide[.t.benchSubject;`read;`data.bench]}];
  -1 "        single authorize decision: ",(string us)," us/call (1000-row grant table)";
  if[us > 50; '"a single decision took ",(string us)," us/call — target is low microseconds"];
  }]

/ decide's cover test used to be a per-applicable-grant scan (`any covers[;splitPath r] each g`), so its
/ cost scaled with the number of applicable grants: a request the policy refuses has to check every one
/ of them. Ancestor membership replaces the scan with one `in`, so the cost should stay flat as the
/ applicable set grows. Deliberately times a REFUSED request — the worst case for the old scan, and the
/ one that most needs pinning here.
runTest[`benchDecisionIsFlatInPolicySize; {[]
  .t.resetRbac[];
  setGrants[([] grp:3#`benchGroup; act:3#`read; res:`data.a`data.b`data.c)];
  decide[.t.benchSubject;`read;`data.other];                     / warm the memo
  usSmall:.t.us[20000; {[] decide[.t.benchSubject;`read;`data.other]}];
  i:0;
  while[i<200; grant[`benchGroup;`read;`$"data.noise",string i]; i+:1];   / now 203 applicable grants
  decide[.t.benchSubject;`read;`data.other];                     / warm again after the mutation
  usBig:.t.us[20000; {[] decide[.t.benchSubject;`read;`data.other]}];
  -1 "        decision at M=3: ",(string usSmall)," us/call; at M=203: ",(string usBig)," us/call";
  if[usBig > (10*usSmall)+5;
    '"a decision's cost grew with policy size — M=3 was ",(string usSmall)," us/call, M=203 was ",
      (string usBig)," us/call"];
  }]

/ decideMany answers a whole resource vector in one pass rather than kx.auth's liftScalar calling
/ `decide` once per resource. Pins per-resource cost on a batch that is mostly refused (the shape that
/ most needs a wide obligation set built correctly), not just answered-yes. A smaller rep count than
/ the single-decision benchmark, since each rep is itself a whole N-resource batch.
runTest[`benchBatchDecisionIsOnePass; {[]
  .t.resetRbac[];
  setGrants[.t.bigGrants 1000];
  N:5000;
  / .t.benchRs is a GLOBAL: a local here would not be visible once passed through .t.us's niladic
  / lambda, per the same trap loadOfAMalformedFileLeavesThePriorSetInForce documents — stash it.
  .t.benchRs:`$"data.area",/:(string til N),\:".tbl";  / same shape .t.bigGrants gives its OWN grants,
                                                         / none of which benchGroup holds — mostly refused
  decideMany[.t.benchSubject;`read;.t.benchRs;emptyCtx];      / warm the memo
  us:.t.us[50; {[] decideMany[.t.benchSubject;`read;.t.benchRs;emptyCtx]}];
  nsPerRes:1000*us%N;
  -1 "        batch decision: ",(string nsPerRes)," ns/resource (N=",(string N),")";
  if[nsPerRes > 2000; '"a batch decision cost ",(string nsPerRes)," ns/resource — expected well under 1us"];
  }]

/ ---- 2. the memo is correct, not just fast --------------------------------------------------------
/ A cache that returns a stale answer is worse than no cache at all, and in an authorization engine it is
/ a security bug. These pin the invalidation rather than the speed.
runTest[`memoIsInvalidatedByEveryMutationVerb; {[]
  .t.resetRbac[];
  p:.t.subj[`traders];
  if[decide[p;`read;`data.trades]; '"precondition: expected no grant yet"];

  grant[`traders;`read;`data.trades];               / grant must invalidate
  if[not decide[p;`read;`data.trades]; '"a grant did not invalidate the memo — a stale DENY survived"];

  revoke[`traders;`read;`data.trades];              / revoke must invalidate
  if[decide[p;`read;`data.trades]; '"a revoke did not invalidate the memo — a stale ALLOW survived"];

  setGrants[([] grp:enlist `traders; act:enlist `read; res:enlist `data.trades)];
  if[not decide[p;`read;`data.trades]; '"setGrants did not invalidate the memo"];

  setGrants[([] grp:`symbol$(); act:`symbol$(); res:`symbol$())];
  if[decide[p;`read;`data.trades]; '"emptying the table did not invalidate the memo"];
  }]

/ The test above always mutates and queries under the SAME exact groups vector, so it can't tell
/ correct wholesale invalidation apart from a hypothetical "scope invalidation to the exact grant row
/ touched" optimization that only clears memo entries keyed by that exact vector. Use a WIDER principal
/ whose groups merely CONTAIN the mutated grp, not equal it, so a per-key-only bug would miss it.
runTest[`memoInvalidationIsWholesaleAcrossDifferentGroupVectors; {[]
  .t.resetRbac[];
  wide:.t.subj[`trader`viewer];
  if[decide[wide;`read;`data.trades]; '"precondition: expected no grant yet"];
  grant[`trader;`read;`data.trades];
  if[not decide[wide;`read;`data.trades];
    '"a grant to a narrower-but-overlapping group did not invalidate a wider principal's cached memo entry"];
  }]

/ A stale ALLOW is the dangerous direction, so pin it through the real seam as well as the raw decision.
runTest[`revokeTakesEffectImmediatelyThroughTheSeam; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  .t.installRbac[];
  setLoginGroups[(enlist .t.u)!enlist `traders];
  if[not `traders in (authorize[`read;`data.trades])`groups; '"precondition: the grant did not take effect"];
  if[not (enlist `data.trades) ~ entitled[`read;`data.trades]; '"precondition: entitled disagreed"];
  revoke[`traders;`read;`data.trades];
  .t.mustDeny[{[] authorize[`read;`data.trades]}];
  if[count entitled[`read;`data.trades]; '"entitled still answered from a stale memo after a revoke"];
  }]

/ Everything above proves invalidation is OBSERVABLE — the next decision is right — because `applicable`
/ compares memoVersion to policyVersion and clears LAZILY, on its own next call (init.q:36). The stronger
/ property public/CLAUDE.md states is that the memo must never OUTLIVE a mutation: the stale entries
/ should be gone when the mutation returns, not merely ignored by whoever reads next. Before `invalidate`
/ they sat in memory indefinitely if nothing read again, which is also what let the unbounded-growth half
/ of this finding accumulate. Asserted on `count memo` rather than on a decision, because a decision can
/ only ever see the post-clear state and so cannot distinguish eager from lazy at all. Finding kx.rbac #1
/ (invalidation half).
runTest[`memoIsDroppedByTheMutationItself; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  decide[.t.subj[`traders];`read;`data.trades];        / populate the memo
  if[0=count memo; '"precondition: the memo did not populate"];
  grant[`viewers;`query;`kdbx.sql];                   / a mutation must drop it here, not later
  if[count memo;
    '"the memo outlived the mutation — ",(string count memo)," entr(y/ies) still cached at policyVersion ",
      (string policyVersion)," with memoVersion ",string memoVersion];
  }]

/ The memo must key on the ACTION as well as the groups, or one action's answer would serve another.
runTest[`memoKeysOnActionAndGroups; {[]
  .t.resetRbac[];
  grant[`traders;`read;`data.trades];
  p:.t.subj[`traders];
  if[not decide[p;`read;`data.trades]; '"the read grant did not decide"];
  if[decide[p;`write;`data.trades]; '"the `read memo entry answered a `write question"];
  if[decide[.t.subj[`others];`read;`data.trades]; '"the `traders memo entry answered for another group"];
  }]
