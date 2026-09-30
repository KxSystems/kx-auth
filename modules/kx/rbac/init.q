/ kx.rbac — group/action/resource policy engine for kx.auth.
/ .
/ Grants are `(grp;act;res)` rows. Actions match exactly; resource grants cover dotted descendants.
/ A null action or resource is a wildcard. The model is allow-only and has no verb subsumption.

/ ============================ state ============================
/ `seg` is derived at mutation time.
grantStore:([] grp:`symbol$(); act:`symbol$(); res:`symbol$(); seg:());

/ Every mutation invalidates the memo through this version.
policyVersion:0;

/ Memo: (groups;action) -> applicable pre-split paths.
memo:()!();
memoVersion:0;

/ Configured locally at startup; remote persistence never accepts a path.
storePath:(::);

/ Every mutation invalidates WHOLESALE in the same expression that bumps the version, so no stale entry
/ can outlive the mutation that made it wrong. `applicable`'s own lazy check stays: tests (and any code)
/ that write `grantStore` directly never come through here. The generic `()!()` flavour is load-bearing —
/ the memo key is a general 2-list.
invalidate:{[] policyVersion::policyVersion+1; memo::()!(); memoVersion::policyVersion; };

/ ============================ the cover relation ============================
/ The empty path represents the resource wildcard.
splitPath:{[r] $[null r; `$(); `$"." vs string r]};

/ Segment-prefix cover; the empty grant path covers every resource. Used by holdersOf/explain, which
/ walk a candidate table's `seg` rather than the live grant set `decide` reads (see below).
covers:{[g;r] $[0=count g; 1b; g~(count g) sublist r]};

/ Every ancestor path of r, r itself included: `data.chat.wealth -> `data`data.chat`data.chat.wealth.
/ Empty for a null resource, which only a wildcard grant covers. "." sv "." vs x is the identity on any
/ string, so mapping a segment prefix back to a symbol decides exactly what `covers` on split segments
/ decided -- this is the same relation restated as membership rather than a per-grant scan.
ancestorsOf:{[r]
  if[null r; :`$()];
  s:string r;
  `$((where "."=s),count s)#\:s };

/ Invalid or groupless subjects match no grants. The `groups` VALUE is type-checked too, not just the
/ outer shape: a present-but-non-symbol value would otherwise reach qSQL's `grp in groups` in
/ `applicablePaths`/`effective`/`explain` and 'type — and a decision path that THROWS is not a denial.
/ Nested rather than `and`: `and` is eager, and a missing-key read on a symbol-valued dict answers the
/ NULL SYMBOL (type -11h), which would pass an eager conjunct's type test.
groupsOf:{[p]
  if[not 99h=type p; :`$()];
  if[not `groups in key p; :`$()];
  g:(),p`groups;
  $[11h=type g; g; `$()] };

/ ============================ the decision ============================
/ Applicable resources for a subject's groups and one action. A null entry is a resource-wildcard
/ grant. Memoised below on the (groups;action) pair, same as before this held `seg`.
applicablePaths:{[groups;action] exec res from grantStore where grp in groups, (null act) or act=action};

/ Memoize by `(groups;action)`.
applicable:{[groups;action]
  if[memoVersion<>policyVersion; memo::()!(); memoVersion::policyVersion];
  k:(groups;action);
  if[$[0=count memo; 1b; not k in key memo];
    memo::memo,(enlist k)!enlist applicablePaths[groups;action]];
  memo k };

/ r is covered iff one of r's own ancestors (r included) is exactly one of the applicable grants, or
/ any applicable grant is the resource wildcard. One `in` over the whole applicable set replaces the
/ old per-grant `covers` scan, so a decision stops scaling with the number of applicable grants.
decide:{[p;a;r]
  g:applicable[groupsOf p; a];
  $[0=count g; 0b;
    any null g; 1b;
    any (ancestorsOf r) in g] };

/ ============================ control-plane viability ============================
/ Groups that hold an action/resource grant in a candidate table.
holdersOf:{[t;a;r]
  if[0=count t; :`$()];
  want:splitPath r;
  distinct (t`grp) where ((null t`act) or t[`act]=a) and covers[;want] each t`seg };

anyoneHolds:{[t;a;r] 0 < count holdersOf[t;a;r]};

/ Grants required for remote identity assertion and policy administration.
vitalGrants:((`assert; `kx.identity; "assert an identity, so no user session could be established");
           (`admin;  `kx.rbac;     "administer the policy, so no remote caller could repair it"));

/ Refuse only a transition that removes the last holder of a vital grant. Keep the remote signal within
/ q's 254-character limit; print the full local diagnostic.
guardVital:{[cand]
  {[cand;v]
    a:v 0; r:v 1; why:v 2;
    was:holdersOf[grantStore; a; r];
    if[0=count was; :(::)];
    if[anyoneHolds[cand; a; r]; :(::)];
    pair:(string a),":",string r;
    shown:$[3<count was; (" " sv string 3 sublist was)," +",(string -3+count was)," more"; " " sv string was];
    -1 "kx.rbac: REFUSED a change that would leave no group able to ",pair,".\n",
       "  ",why,"\n",
       "  Held right now by: ",(" " sv string was),"\n",
       "  Nothing can restore it remotely, so recovery would need console access to this q process.\n",
       "  If you are replacing the policy, include a ",pair," row in the same call.";
    '"kx.rbac REFUSED: no group would be left able to ",pair,
     ". Include that row in the same call; it cannot be restored remotely, so recovery would need ",
     "console access to this q process. Held now by: ",shown
   }[cand] each vitalGrants; };

/ ============================ validation ============================
/ Resource paths are null wildcards or dotted paths with no empty segment.
validPath:{[r] $[null r; 1b; all 0 < count each string splitPath r]};

/ Validate grant values after the caller has established the exact public columns.
validateGrantRows:{[t]
  e:();
  wrong:where not 11h = type each t`grp`act`res;
  if[count wrong; e,:enlist "column(s) must be symbol: ", " " sv string `grp`act`res wrong];
  if[count e; :e];
  if[any null t`grp; e,:enlist "group must not be null"];
  bad:(t`res) where not validPath each t`res;
  if[count bad; e,:enlist "malformed resource path(s): ", " " sv string distinct bad];
  e };

/ Validate columns, types, path shape and duplicates. Actions are deployment-defined.
validate:{[t]
  if[not 98h=type t; :enlist "expected a table with columns grp, act, res"];
  missing:`grp`act`res except cols t;
  if[count missing; :enlist "missing column(s): ", " " sv string missing];
  extra:cols[t] except `grp`act`res;
  if[count extra; :enlist "unexpected column(s): ", " " sv string extra];
  e:validateGrantRows t;
  if[count e; :e];
  dup:where 1 < count each group `grp`act`res#t;
  if[count dup; e,:enlist "duplicate grant row(s): ", " " sv {"(",("," sv string value x),")"} each dup];
  e };

/ Validate a transaction's ordered grant/revoke operations. The CLI and gateways use this table as the
/ language-neutral mutation protocol; it is deliberately smaller than q code and contains no paths.
validateOperations:{[t]
  if[not 98h=type t; :enlist "expected a table with columns op, grp, act, res"];
  missing:`op`grp`act`res except cols t;
  if[count missing; :enlist "missing operation column(s): ", " " sv string missing];
  extra:cols[t] except `op`grp`act`res;
  if[count extra; :enlist "unexpected operation column(s): ", " " sv string extra];
  e:();
  wrong:where not 11h = type each t`op`grp`act`res;
  if[count wrong; e,:enlist "operation column(s) must be symbol: ", " " sv string `op`grp`act`res wrong];
  if[count e; :e];
  bad:distinct (t`op) where not (t`op) in `grant`revoke;
  if[count bad; e,:enlist "unknown operation(s): ", " " sv string bad];
  e,:validateGrantRows `grp`act`res#t;
  e };

/ Add the derived resource segments.
presplit:{[t]
  t:`grp`act`res#t;
  t,'flip (enlist `seg)!enlist splitPath each t`res };

/ Validate before replacing the live grant set.
replaceGrants:{[t;verb;args]
  e:validate t;
  if[count e; '"kx.rbac: invalid grant table — ", "; " sv e];
  cand:presplit t;
  guardVital cand;
  grantStore::cand;
  invalidate[];
  audit[verb; args; count grantStore];
  count grantStore };

/ Apply ordered operations to a public grant table without touching live state. Repeated grants and
/ revokes are idempotent; an import can therefore be retried safely after an uncertain client failure.
applyOperation:{[t;r]
  $[`grant=r`op;
    $[count select from t where grp~\:r`grp, act~\:r`act, res~\:r`res;
      t;
      t upsert (r`grp;r`act;r`res)];
    delete from t where grp~\:r`grp, act~\:r`act, res~\:r`res] };

candidateFromOperations:{[ops]
  e:validateOperations ops;
  if[count e; '"kx.rbac: invalid operation table — ", "; " sv e];
  applyOperation/[grants[];ops] };

setGrants:{[t]
  requireAdmin[];
  replaceGrants[t;`setGrants;enlist count t] };

/ ============================ the administration gate ============================
/ Remote mutations authorize the principal in effect. Local calls bypass the gate because local q code
/ can already modify module state.
requireAdmin:{[]
  if[0=.z.w; :1b];
  .kx.auth.authorize[`admin; `kx.rbac];
  1b };

/ Audit remote mutations.
audit:{[verb;args;n]
  if[0<>.z.w;
    p:.kx.auth.current[];
    -1 "kx.rbac: ",string[p`sub]," via ",string[.z.u]," ",string[verb]," ",
       ("," sv -3!'args)," -> ",string[n]," row(s)"]; };

/ ============================ mutation ============================
/ Validate one public grant row.
validateRow:{[verb;g;a;r]
  if[not all -11h = type each (g;a;r);
    '"kx.rbac.",(string verb),": group, action and resource must be symbol atoms"];
  if[null g; '"kx.rbac.",(string verb),": group must not be null"];
  if[not validPath r; '"kx.rbac.",(string verb),": malformed resource path: ", -3!r]; };

/ Add one grant idempotently.
grant:{[g;a;r]
  requireAdmin[];
  validateRow[`grant;g;a;r];
  if[count select from grantStore where grp~\:g, act~\:a, res~\:r; :count grantStore];
  grantStore::grantStore upsert (g;a;r;splitPath r);
  invalidate[];
  audit[`grant; (g;a;r); count grantStore];
  count grantStore };

/ Remove one exact grant row.
revoke:{[g;a;r]
  requireAdmin[];
  validateRow[`revoke;g;a;r];
  cand:delete from grantStore where grp~\:g, act~\:a, res~\:r;
  guardVital cand;
  grantStore::cand;
  invalidate[];
  audit[`revoke; (g;a;r); count grantStore];
  count grantStore };

/ ============================ inspection ============================
/ Return the public grant columns.
grants:{[] `grp`act`res#grantStore};

/ Return rows held by the subject's groups.
effective:{[p]
  gs:groupsOf p;
  select from grants[] where grp in gs };

/ Pure decision for an explicit principal.
check:{[p;a;r] decide[p;a;r]};

pair:{[a;r] (string $[null a; `; a]),":",string $[null r; `; r]};

/ Explain the first stage at which no grant remains applicable.
explain:{[p;a;r]
  gs:groupsOf p;
  want:splitPath r;
  bySubject:select from grantStore where grp in gs;
  byAction:select from bySubject where (null act) or act=a;
  hits:byAction where covers[;want] each byAction`seg;
  reason:$[
    count hits;        "granted by ", "; " sv {[x] (string x`grp)," ",pair[x`act;x`res]} each hits;
    0=count gs;        "the subject holds no groups, so no grant can apply";
    0=count bySubject; "no grants at all for group(s) ", " " sv string gs;
    0=count byAction;  "group(s) ",(" " sv string gs)," hold no ",(string a)," grant (they hold: ",
                         (", " sv distinct {pair[x`act;x`res]} each bySubject),")";
    "no grant covers ",pair[a;r]," for group(s) ",(" " sv string gs),
      " (nearest ",(string a)," grants: ",(", " sv distinct string exec res from byAction),")"];
  `allowed`pair`groups`matched`reason!(0<count hits; pair[a;r]; gs; `grp`act`res#hits; reason) };

/ ============================ persistence ============================
/ Accept a file symbol or string path. `hsym` is idempotent, so a string that already carries its colon
/ (what a getenv-supplied path can look like) is not doubled into an unusable `::` path the way a bare
/ ":" prepend would double it.
pathOf:{[path]
  p:$[10h=type path; hsym `$path; path];
  if[not -11h=type p; '"kx.rbac: expects a file path, e.g. `:/etc/kx/grants"];
  p };

/ A directory cannot be the store. `mv` would move the snapshot INTO it and succeed, so a write would
/ report persisted while `load[]` reads the directory and refuses it. `key` is 11h for any directory,
/ empty or not, -11h for a file and () for a missing path.
refuseDir:{[who;p]
  if[11h=type key p; 'who,": the store path is a directory, not a file: ",1_string p]; p };

/ Only local startup code chooses the policy-store path.
configureStore:{[path]
  if[0<>.z.w; '"kx.rbac.configureStore: local calls only"];
  storePath::refuseDir["kx.rbac.configureStore"; pathOf path];
  storePath };

requireStore:{[]
  if[(::)~storePath; '"kx.rbac: no policy store configured; call configureStore[path] locally at startup"];
  storePath };

/ Quote one argument for the POSIX shell used by system.
shellQuote:{[s] "'",ssr[s;"'";"'","\\","''"],"'"};

/ Save the public columns using a same-filesystem temp-then-rename. The directory check is repeated here
/ because one can appear at the path after configureStore; it runs before the temp file is written.
writeSnapshot:{[t]
  p:refuseDir["kx.rbac"; requireStore[]];
  tmp:`$(string p),".tmp";
  tmp set t;
  system "mv -- ",(shellQuote 1_string tmp)," ",shellQuote 1_string p;
  p };

saveTo:{[]
  requireAdmin[];
  p:writeSnapshot grants[];
  audit[`save;();count grantStore];
  p };

/ Load, validate and replace the current set.
loadFrom:{[]
  requireAdmin[];
  p:requireStore[];
  if[() ~ key p; '"kx.rbac.load: no such file: ",1_string p];
  t:@[get; p; {[e] '"kx.rbac.load: cannot read the file: ",e}];
  replaceGrants[t;`load;enlist p] };

/ ============================ verify — the maintenance lint ============================
/ Return policy-wide findings as (severity;issue;detail). The candidate form lets a dry-run lint the
/ policy it would create, rather than misleadingly reporting on the still-live policy.
/ `t` is always a PRESPLIT table, so the `seg` column already holds what a re-split would recompute.
verifyCandidate:{[t]
  out:();
  asserters:holdersOf[t;`assert;`kx.identity];
  admins:holdersOf[t;`admin;`kx.rbac];

  if[0=count asserters;
    out,:enlist (`error; "no group can assert an identity";
      "no grant confers `assert on `kx.identity, so no user session can be established. Grant it to the trusted intermediary's login tier.")];

  if[0=count admins;
    out,:enlist (`warning; "no group can administer the policy";
      "no grant confers `admin on `kx.rbac, so the policy can only be changed from this q session. Fine if deliberate; a lockout if not.")];

  / An unbound handle decides as the connecting login.
  dataRows:select from t where not (first each seg) in `kx;
  leaky:distinct (dataRows`grp) inter asserters;
  if[count leaky;
    out,:enlist (`warning; "an asserter tier also holds non-control-plane grants";
      ("group(s) ",(" " sv string leaky)," can assert AND hold grants outside `kx.*. Because an unbound ",
       "handle decides as the connecting login, a missing bind would reach that data instead of being refused."))];

  / A total wildcard cannot express exceptions.
  total:exec grp from t where null act, null res;
  if[count total;
    out,:enlist (`note; "a total wildcard grant exists";
      ("group(s) ",(" " sv string distinct total)," hold `:` (any action, any resource). Exceptions become ",
       "inexpressible, since there are no deny rules. Prefer a per-root wildcard, e.g. grant[g;`;`data]."))];

  $[count out;
    flip `severity`issue`detail!flip out;
    ([] severity:`symbol$(); issue:(); detail:())] };

verify:{[] verifyCandidate grantStore};

/ ============================ atomic transactions ============================
transactionResult:{[before;cand;dry;findings]
  added:cand except before;
  removed:before except cand;
  `dryRun`changed`beforeCount`afterCount`added`removed`findings`wouldPersist`persisted!
    (dry;0<(count added)+count removed;count before;count cand;added;removed;findings;not (::)~storePath;0b) };

/ `cand` is the bare table that gets persisted; `split` is the same rows with their derived segments,
/ already computed once by the caller. Taking both avoids re-deriving what the transaction has proven.
commitCandidate:{[cand;split;verb;args;result]
  requireAdmin[];
  writeSnapshot cand;
  grantStore::split;
  invalidate[];
  audit[verb;args;count grantStore];
  result[`persisted]:1b;
  result };

/ Validate, guard, lint and optionally persist a batch as one policy transition. Dry-runs are public
/ inspection, just like check/explain; only the committing branch crosses the administration gate.
applyPersisted:{[ops;dryRun]
  if[not -1h=type dryRun; '"kx.rbac.apply: dryRun must be a boolean atom"];
  before:grants[];
  cand:candidateFromOperations ops;
  / Derive the segments ONCE. The guard, the lint and the installed table must all describe the same
  / candidate, and recomputing it per step invites them to drift apart.
  split:presplit cand;
  guardVital split;
  result:transactionResult[before;cand;dryRun;verifyCandidate split];
  if[dryRun; :result];
  commitCandidate[cand;split;`apply;enlist count ops;result] };

/ Whole-policy replacement is intentionally explicit. Ordinary imports use operations; snapshots may
/ call this only when the operator chose --replace.
replacePersisted:{[t;dryRun]
  if[not -1h=type dryRun; '"kx.rbac.replace: dryRun must be a boolean atom"];
  e:validate t;
  if[count e; '"kx.rbac: invalid grant table — ", "; " sv e];
  before:grants[];
  cand:`grp`act`res#t;
  split:presplit cand;
  guardVital split;
  result:transactionResult[before;cand;dryRun;verifyCandidate split];
  if[dryRun; :result];
  commitCandidate[cand;split;`replace;enlist count cand;result] };

/ Print findings and optionally fail on errors.
report:{[fatal]
  v:verify[];
  if[0=count v; -1 "kx.rbac.verify: no issues."; :v];
  {[r] -1 "kx.rbac.verify: ",(upper string r`severity),": ",(r`issue),"\n    ",r`detail; } each v;
  if[fatal and count select from v where severity=`error;
    '"kx.rbac.verify: the policy is unusable — see the errors above"];
  v };

/ ============================ the batch decision ============================
/ Answer a whole resource vector in one pass rather than one `in` per resource. Buckets by the DISTINCT
/ depths present among the applicable grants: for each such depth d, take every request resource's own
/ depth-d ancestor (its first d segments rejoined) and test that whole vector against the depth-d
/ grants in one `in`. D is bounded by how many distinct grant depths a subject's groups make applicable
/ — not by the number of resources requested — so this stays a handful of vectorised passes over the
/ whole batch rather than a per-resource loop. Split and rejoin cost dominates in practice (measured:
/ ~350ns/resource to split the whole batch, ~1ns/resource for the `in` test itself); unlike `decide`,
/ which pays that once for one resource, this pays it once for the WHOLE vector, once per depth.
decideManyCore:{[g;v]
  n:count v;
  if[0=n; :`boolean$()];
  if[0=count g; :n#0b];
  if[any null g; :n#1b];
  gSeg:"." vs/: string g;
  gDepth:count each gSeg;
  depths:distinct gDepth;
  vSeg:"." vs/: string v;
  vDepth:count each vSeg;
  vDepth[where null v]:0;   / a null resource has no ancestors; "." vs string ` gives one EMPTY
                             / segment, which would otherwise put it in the depth-1 bucket
  ok:n#0b;
  i:0;
  while[i<count depths;
    d:depths i;
    gset:distinct `$"." sv/: gSeg where gDepth=d;
    idx:where vDepth>=d;
    if[count idx;
      sub:vSeg idx;
      pfx:`$"." sv/: d#'sub;
      ok[idx]:ok[idx] or pfx in gset];
    i+:1];
  ok };

/ The rank-4 form kx.auth.setPolicy accepts: (principal;action;resources;ctx) -> `allowed`obligations.
/ `kx.rbac` owns no context vocabulary, so ctx is ignored and never narrowed. The obligation semantics
/ mirror kx.auth's own scalar-lift (liftScalar): a `resources` obligation appears only when the
/ permitted set is a STRICT subset, so an unnarrowed request carries no obligations at all. The
/ no-obligation dict is written as the same literal kx.auth's own reference and skill teach a
/ host-authored policy to write — see docs/q-gotchas.md and modules/kx/auth/docs/references/auth.md —
/ rather than exported, since every export in either module's dict is a function.
decideMany:{[p;a;rs;ctx]
  v:(),rs;
  g:applicable[groupsOf p; a];
  ok:decideManyCore[g;v];
  $[all ok;
    `allowed`obligations!(1b; (`symbol$())!());
    `allowed`obligations!(any ok; (enlist `resources)!enlist v where ok)] };

/ Policy function accepted by kx.auth.setPolicy[]. Rank 4: kx.rbac answers a whole resource vector in
/ one pass rather than making kx.auth's liftScalar call `decide` once per resource. `check` and the
/ test suite call `decide` directly and are unaffected.
policySpec:{[] decideMany};

/ ============================ public surface ============================
/ Append new exports: aimeta-compiled consumers may key the established dict positionally, so inserting
/ entries would change prior compiled output even though every existing name still exists.
export:`grant`revoke`setGrants`grants`effective`check`explain`verify`report`configureStore`save`load`policy`apply`replace!(grant;revoke;setGrants;grants;effective;check;explain;verify;report;configureStore;saveTo;loadFrom;policySpec;applyPersisted;replacePersisted);
