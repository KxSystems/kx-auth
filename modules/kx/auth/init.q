/ kx.auth — upstream identity assertion and default-deny authorization for kdb+.
/ .
/ The connecting login authenticates the connection; bind[] attaches an upstream-authenticated
/ principal to it. q performs no token validation or cryptography. bind[] requires the connecting
/ login to hold `assert on `kx.identity under the installed policy.
/ .
/ Assign the module globally so remote calls resolve: .kx.auth:use`kx.auth.
/ Resources under `kx.* are reserved for the module control plane.

/ ============================ private state ============================
/ Store principals as one-row tables so rebinding replaces the complete value.
bound:(`int$())!();

/ HTTP identity is request-scoped because keep-alive sockets may be reused.
reqPrincipal:(::);

/ Case-insensitive header carrying the gateway-validated principal JSON.
principalHeader:`$"x-kx-principal";

/ When enabled, HTTP assertion trusts the network perimeter and audits every use.
httpTrustPerimeter:0b;

/ Configured claim paths used by promote[].
claimPaths:`groups`tenant!("";"tenant");
groupSearch:("groups";"realm_access.roles";"roles");   / default order when claimPaths`groups is ""

/ Optional service-account credential; an empty value defers to the prior .z.pw.
svc:(`;"");

/ Login-to-groups map. Unmapped logins have no groups.
logins:(`symbol$())!();

/ Authorization hook. A policy is EITHER the scalar `(principal;action;resource) -> boolean` contract or
/ the context-aware `(principal;action;resources;ctx) -> obligations` one. setPolicy accepts both and
/ records which, so the scalar hot path stays exactly what it was. Default deny.
denyAll:{[principal;action;resource] 0b};
policy:denyAll;
policyRank:3;

/ The one empty-context value the module constructs or compares against. Flavour matters: `type key ()!()`
/ is 0h while `` type key (`symbol$())!() `` is 11h, and `()!() ~ (`symbol$())!()` SIGNALS 'length rather
/ than answering 0b. Everything here goes through this value so no comparison can hit that.
emptyCtx:(`symbol$())!();

/ Protected functions are projections over private dispatchers. A unique token joins each wrapper to
/ its loaded @authorize requirement; originals never appear in the public projections.
nextProtectToken:0;
protectedOriginals:();
protectedWrappers:();
declared:([] token:`long$(); name:`symbol$(); act:`symbol$(); res:`symbol$());

/ Prior .z handlers retained for composition.
priorPw:{[u;p] 1b};
priorPo:{[w] };
priorPc:{[w] };
priorPh:{[x] };
priorPp:{[x] };
priorPg:{[x] value x};
priorPs:{[x] value x};

/ Activation is idempotent within each handler family.
active:0b;
httpActive:0b;
perimeterActive:0b;

/ ============================ canonicalisation / promotion ============================
/ promote[] canonicalizes principals from every transport. Raw claims remain unchanged.

/ Resolve a dotted path; return (::) when any segment is absent.
dig:{[d;path] {[r;k] $[99h=type r; $[k in key r; r k; (::)]; (::)]}/[d; `$"." vs path]};

asSym:{[x] $[10h=type x; `$x; x]};
asSyms:{[x] $[10h=type x; enlist `$x; (0h=type x) and all 10h=type each x; `$x; -11h=type x; enlist x; x]};

extractGroups:{[claims]
  paths:$[count claimPaths`groups; enlist claimPaths`groups; groupSearch];
  v:dig[claims] each paths;
  good:v where not (::)~/:v;
  $[count good; asSyms first good; `$()] };

/ Convert unix-seconds `exp values to timestamps. Accepts every numeric atom WIDE ENOUGH to hold an
/ epoch, not just the long PyKX produces and the float .j.k produces: an unconverted `exp compares raw
/ against .z.p, whose unit is nanoseconds since 2000, so epoch seconds read as a moment just after
/ 2000.01.01 and lock out a principal whose expiry is years away. A short or byte cannot represent any
/ realistic epoch, and a list or string cannot be one, so those are deliberately left unconverted —
/ they then compare as long expired and deny, which is the right answer for a malformed claim.
canon:{[p]
  if[(`exp in key p) and (type p`exp) in -6 -7 -8 -9h;
    p[`exp]:1970.01.01D0 + 1000000000 * `long$p`exp];
  p };

/ The shape contract, checked AFTER the coercions in promote. Everything downstream — valid, denialText,
/ kx.rbac's `grp in groups` — reads these fields by type, so a value that survives promotion in the wrong
/ shape crashes the first decision instead of being refused at the boundary. Coercion is the lenient half;
/ what it could not coerce, this refuses. One fault, the first found, naming the field and the q type it
/ saw (never the value: a refusal is answered to the sender, who may be hostile).
shapeFault:{[p]
  s:p`sub;
  if[not -11h=type s; :"sub must be a non-null symbol atom, got ",-3!type s];
  if[null s; :"sub must be a non-null symbol atom, got a null symbol — a principal with no identity does not bind"];
  k:key p;
  if[(`client in k) and not -11h=type p`client; :"client must be a symbol atom, got ",-3!type p`client];
  if[(`iss in k) and not -11h=type p`iss; :"iss must be a symbol atom, got ",-3!type p`iss];
  if[(`tenant in k) and not -11h=type p`tenant; :"tenant must be a symbol atom, got ",-3!type p`tenant];
  if[not 11h=type p`groups; :"groups must be a symbol vector, got ",-3!type p`groups];
  if[(`aud in k) and not 11h=type p`aud; :"aud must be a symbol vector, got ",-3!type p`aud];
  if[(`scopes in k) and not 11h=type p`scopes; :"scopes must be a symbol vector, got ",-3!type p`scopes];
  / -12h too: promote is idempotent on its own output, and a q host may hand over a timestamp directly.
  if[(`exp in k) and not (type p`exp) in -5 -6 -7 -8 -9 -12h;
    :"exp must be a numeric atom of unix seconds, got ",-3!type p`exp];
  if[(`claims in k) and not 99h=type p`claims; :"claims must be a dictionary, got ",-3!type p`claims];
  (::) };

promote:{[p]
  e:dictFault[p;"a principal"];
  if[not (::)~e; '"kx.auth: malformed principal: ",e];
  c:$[(`claims in key p) and 99h=type p`claims; p`claims; ()!()];
  p:p,(enlist `groups)!enlist $[`groups in key p; asSyms p`groups; extractGroups c];
  / scalar identity fields
  sf:`sub`client`iss inter key p;
  p[sf]:asSym each p sf;
  if[`aud in key p; p[`aud]:asSyms p`aud];
  if[`scopes in key p; p[`scopes]:asSyms p`scopes];
  / prefer a top-level tenant
  t:$[`tenant in key p; p`tenant; (count claimPaths`tenant) and 99h=type c; dig[c; claimPaths`tenant]; (::)];
  if[not (::)~t; p[`tenant]:asSym t];
  / derive a missing subject from claims or client
  if[(not `sub in key p) or (`~p`sub); p[`sub]:$[`sub in key c; asSym c`sub; p`client]];
  / ASCII only: this signal crosses qIPC, and PyKX decodes a q error's bytes as latin-1, so a non-ASCII
  / separator reaches the CLI user as mojibake.
  e:shapeFault p;
  if[not (::)~e; '"kx.auth: malformed principal: ",e];
  canon p };

/ Always return a group vector for a login.
loginGroups:{[u] $[u in key logins; (),logins u; `$()]};

/ Canonical principal derived from a kdb+ login. Built canonical rather than promoted: every part is
/ already the shape promote produces (a symbol from .z.u, a symbol vector from the validated login map, a
/ literal issuer), so promote would be the identity on it — pinned by loginPrincipalIsAFixedPointOfPromote.
/ Skipping it keeps the strictness check off the per-request path, and lets an anonymous login (a client
/ that sent no credentials has `.z.u` null) decide as nobody rather than be refused as malformed.
loginPrincipal:{[u] `sub`groups`iss!(u; loginGroups u; `kdb.local)};

/ ============================ core verbs ============================
/ Bind a promoted principal after authorizing the connecting login to assert identity.
bind:{[principal]
  if[not allows[loginPrincipal .z.u; `assert; `kx.identity];
    '"denied: caller ",string[.z.u]," not permitted to assert identity (grant `assert on `kx.identity, and map the login with setLoginGroups)"];
  bound::bound,(enlist .z.w)!enlist enlist promote principal; };

/ Current subject: HTTP request, bound qIPC principal, or connecting login.
current:{[] $[not (::)~reqPrincipal; reqPrincipal; .z.w in key bound; first bound .z.w; loginPrincipal .z.u]};

/ A principal without `exp does not expire.
valid:{[]
  p:current[];
  if[(::)~p; :0b];
  if[not `exp in key p; :1b];
  p[`exp] > .z.p };

/ Return the current principal or signal when it is invalid.
require:{[]
  if[not valid[]; '"denied: no valid principal in effect on this handle (expired)"];
  current[] };

/ ============================ authorization seam (S/A/R + context) ============================
/ ONE decision path, three published arities. `scope` is the general verb: many resources, an optional
/ declared context, and OBLIGATIONS out. `authorize` and `entitled` are its shortcuts and their contracts
/ do not move — a plural request against a scalar policy is exactly the per-resource loop `entitled` has
/ always run, so nothing needs a placeholder resource (a null resource means "holds a wildcard grant", not
/ "holds anything", which is why the general path takes the vector rather than a sentinel).
/ .
/ An OBLIGATION is a narrowing the caller must apply: `` `resources `` for the permitted subset, plus
/ whatever axes the caller declared in its context. An EMPTY obligation set is an unconditional allow. An
/ empty narrowing on an axis is an allow that yields nothing — never "no constraint".

/ Validate anything the seam accepts as a context or an obligation set. A keyed table is also 99h, and
/ duplicate keys survive an upsert (`` d:(`a`a)!(1 2) `` updated by `` `a `` keeps the stale second value),
/ so both are refused rather than half-applied.
dictFault:{[d;what]
  if[not 99h=type d; :what," must be a dictionary"];
  if[98h=type value d; :what," must be a dictionary, not a keyed table"];
  k:key d;
  if[count k;
    if[not 11h=type k; :what," keys must be symbols"];
    if[(count distinct k)<>count k; :what," has duplicate keys"]];
  (::) };

/ Context is OPTIONAL, and q has fixed arity, so `(::)` — the idiom for an argument not supplied — means
/ "no context declared". A caller that has nothing to declare writes `scope[action;resources;::]` and is
/ back to the simple case. Either empty-dict flavour is accepted too, since a caller building a context
/ dynamically may produce the generic one.
/ Any empty dict normalises to the pinned flavour, not just `(::)`. `()!()` is actively hostile: it signals
/ 'length when concatenated onto (`()!() , (enlist `a)!enlist 1`) and 'type when index-assigned a vector, so
/ letting one in would make the seam's behaviour depend on which flavour a caller happened to build.
normaliseCtx:{[ctx] $[(::)~ctx; emptyCtx; $[(99h=type ctx) and 0=count ctx; emptyCtx; ctx]]};

/ A context declares the axes a policy is allowed to narrow. `resources` is always declared implicitly, so
/ it may not be redeclared here.
ctxFault:{[ctx]
  e:dictFault[ctx;"a context"];
  if[not (::)~e; :e];
  if[`resources in key ctx; :"`resources is reserved — it is always declared, so pass it as the resources argument"];
  (::) };

/ Lift a scalar policy onto the general path. A `resources` obligation appears only when the permitted set
/ is a STRICT subset, so an unnarrowed request carries no obligations at all and `authorize` sees none.
liftScalar:{[principal;action;resources;ctx]
  ok:policy[principal;action;] each resources;
  $[all ok;
    `allowed`obligations!(1b; emptyCtx);
    `allowed`obligations!(any ok; (enlist `resources)!enlist resources where ok)] };

/ The single decision site. Never signals a refusal — it reports one, so `explain` can show it and `scope`
/ can raise it. It DOES signal when the installed policy answers malformed, because that is a host bug and
/ failing closed on it silently would hide the cause.
decideRequest:{[principal;action;resources;ctx]
  rs:(),resources;
  d:$[4=policyRank; policy[principal;action;rs;ctx]; liftScalar[principal;action;rs;ctx]];
  if[not 99h=type d;
    '"kx.auth: the installed policy answered type ",(-3!type d)," where a decision dictionary was expected"];
  if[not all `allowed`obligations in key d;
    '"kx.auth: the installed policy's decision needs both `allowed and `obligations"];
  if[not -1h=type d`allowed; '"kx.auth: the installed policy's `allowed must be a boolean atom"];
  e:dictFault[d`obligations;"an obligation set"];
  if[not (::)~e; '"kx.auth: ",e];
  o:d`obligations;
  k:key o;
  / A policy may only narrow an axis the caller DECLARED; to constrain anything else it must refuse. `resources`
  / is always implicitly declared, though, so `authorize` — which declares no context — can still be handed a
  / `resources` obligation; it refuses one rather than silently dropping it (see `authorize`'s own comment).
  undeclared:k except `resources,key ctx;
  if[count undeclared;
    '"kx.auth: the installed policy narrowed undeclared axis/axes ",(" " sv string undeclared),
      " — a policy may only narrow what the caller declared, or refuse"];
  decl:((enlist `resources)!enlist rs),ctx;
  / EXACT type equality, not `abs type`. A duration where a timestamp was declared is read as
  / nanos-since-2000 (`2026.08.20D09:00:00 > 900000000000` is 1b), so "clip to 15 minutes" returned as a
  / long would clip to 2000.01.01D00:15 and pass every row, silently.
  wrongType:k where not (type each o k)=type each decl k;
  if[count wrongType;
    '"kx.auth: obligation type mismatch on ",(" " sv string wrongType),
      " — a narrowing must carry the same type the caller declared"];
  / On a list axis a narrowing is checkable without knowing what the axis means. Ordered atoms are not, and
  / are the policy's responsibility: the seam already trusts the policy to decide at all.
  lists:k where 0<type each decl k;
  widened:lists where not {[c;v] (count[v]<=count c) and all v in c}'[decl lists; o lists];
  if[count widened;
    '"kx.auth: the installed policy widened ",(" " sv string widened)," beyond what the caller declared"];
  / The resource axis carries one rule the others do not: narrowed to nothing is a refusal, not an allow.
  allowed:d`allowed;
  if[allowed and (`resources in k) and 0=count o`resources; allowed:0b];
  `allowed`obligations`reason!(allowed; o; $[`reason in key d; d`reason; ""]) };

/ Display form for anything a caller or a policy can put in a denial. `string` on a char vector yields a
/ general LIST, and '` cannot signal one — a hostile or merely mistyped `sub`, `action` or policy `reason`
/ must not turn a denial into a crash. Display-only: `promote` remains the one canonicalisation authority,
/ so this commits nothing about whether asSyms eventually coerces, drops or refuses a hostile claim value.
asText:{[x] $[-11h=type x; string x; 10h=type x; x; -3!x]};

/ `scope` SIGNALS this text and q silently truncates a signalled string at 254 BYTES, which would delete
/ the bootstrap NOTE below whenever it runs behind a long-enough resource list. `explainScope` RETURNS the
/ text and has no such budget, so `cap` only elides the resource list on the signalled path — eliding
/ (rather than reordering the NOTE ahead of it) keeps "<action> on <resource>" adjacent, which callers and
/ demos match on.
denialText:{[principal;action;resources;d;cap]
  rs:(),resources;
  names:asText each rs;
  why:asText d`reason;
  hint:$[(3=policyRank) and policy~denyAll;
    " — NOTE no authorization policy is installed, so everything is refused. Call setPolicy[] at host startup.";
    ""];
  head:"denied: ",(asText principal`sub)," not permitted ",(asText action)," on ";
  tail:$[count why; " — ",why; ""],hint;
  list:" " sv names;
  if[cap and 254 < count head,list,tail;
    n:count where (sums 1+count each names) < 254-16+(count head)+count tail;
    list:(" " sv n sublist names),$[n<count names; " +",(string count[names]-n)," more"; ""]];
  head,list,tail };

/ The CLOSED form of a decision: allowed only when nothing is left to apply. `bind`, `httpMayAssert` and
/ `authorize` declare no context, so a narrowing they are handed cannot be applied — and a gate that cannot
/ apply a narrowing must refuse rather than ignore it. That rule lives here and nowhere else, so the entry
/ points onto decideRequest cannot drift apart again. `resources` is always implicitly declared, which is
/ why a partly-satisfied plural request arrives here as an obligation rather than as a clean deny.
/ .
/ Sits on decideRequest, never on the `policy` slot: the assert gates authorize the connecting LOGIN before
/ any principal exists to require, and calling a rank-4 policy with three arguments would hand it a
/ projection and signal 'type inside `bind`.
closeDecision:{[principal;action;resources]
  d:decideRequest[principal;action;resources;emptyCtx];
  if[(d`allowed) and count d`obligations;
    d[`allowed]:0b;
    d[`reason]:"allowed only subject to obligation(s) on ",(" " sv string key d`obligations),
      ", which this call cannot apply; use scope[action;resources;ctx] to receive and apply a narrowing"];
  d };

allows:{[principal;action;resource] (closeDecision[principal;action;resource])`allowed};

/ The general verb. Enforces, and returns the obligations the caller must apply.
scope:{[action;resources;ctx]
  ctx:normaliseCtx ctx;
  e:ctxFault ctx;
  if[not (::)~e; '"kx.auth.scope: ",e];
  principal:require[];
  d:decideRequest[principal;action;resources;ctx];
  if[not d`allowed; 'denialText[principal;action;resources;d;1b]];
  d`obligations };

/ Inspection, so an obligation can be examined rather than only obeyed. Pure and explicitly-subjected, like
/ kx.rbac.check: enforcement reads the principal in effect, inspection is handed one. Never signals a
/ refusal — it reports it, with whatever reason the policy gave.
explainScope:{[principal;action;resources;ctx]
  ctx:normaliseCtx ctx;
  e:ctxFault ctx;
  if[not (::)~e; '"kx.auth.explain: ",e];
  d:decideRequest[principal;action;resources;ctx];
  d,(enlist `denial)!enlist $[d`allowed; ""; denialText[principal;action;resources;d;0b]] };

/ Enforce the installed policy and return the authorized principal. One resource, no declared context: the
/ decision is CLOSED through closeDecision, the same rule the assert gates read, so an obligation this verb
/ cannot apply is a refusal here and at gateEval, authorizeToken and kx.rbac.requireAdmin alike.
authorize:{[action;resource]
  principal:require[];
  d:closeDecision[principal;action;resource];
  if[not d`allowed; 'denialText[principal;action;resource;d;1b]];
  principal };

/ How many arguments a function still wants. A projection is the case that matters: a host installing
/ `myPolicy[config]` must not silently be read as the other rank and then fail with a bare 'rank or 'type
/ on the first decision. `::` holes are not bound, so `f[;;;;`c]` still wants four. 0N means undecidable —
/ a composition or a primitive — and the caller decides what to do about that.
rankOf:{[fn]
  t:type fn;
  $[100h=t; count (value fn)1;
    104h=t; [v:value fn; (.z.s first v) - count where not (::)~/:1_v];
    0N] };

/ Install the deployment's decision function, at either rank. The rank is read once here rather than per
/ decision, so the scalar path pays nothing for the general one existing.
setPolicy:{[fn]
  if[not (type fn) within 100 112h;
    '"kx.auth.setPolicy: expects a function — (principal;action;resource) -> boolean, or (principal;action;resources;ctx) -> `allowed`obligations!(boolean;dict)"];
  r:rankOf fn;
  / Undecidable stays rank 3: that is what a composition or primitive did before this seam existed, and
  / guessing 4 would change a working deployment's meaning.
  r:$[null r; 3; r];
  if[not r in 3 4;
    '"kx.auth.setPolicy: a policy takes 3 arguments (principal;action;resource) or 4 (principal;action;resources;ctx), not ",string r];
  policy::fn; policyRank::r; fn };

/ Return the permitted subset. Unchanged contract, including answering with an empty vector of the same type
/ rather than signalling: an absent `resources` obligation means nothing was narrowed away.
entitled:{[action;resources]
  rs:(),resources;
  if[0=count rs; :rs];
  p:require[];
  d:decideRequest[p;action;rs;emptyCtx];
  $[not d`allowed; 0#rs;
    `resources in key d`obligations; d[`obligations;`resources];
    rs] };

/ ============================ declared authorization ============================
/ A protected function denies until loadAnnotations[] has installed its static requirement.
authorizeToken:{[token]
  ix:where (declared`token)=token;
  if[1<>count ix;
    '"denied: protected function has no loaded @authorize requirement; call .kx.auth.loadAnnotations[]"];
  row:declared first ix;
  authorize[row`act;row`res] };

/ Fixed dispatcher ranks preserve the wrapped lambda's public calling convention. The final niladic
/ argument in protect0 is the projection hole consumed by q's f[] call.
protect0:{[token;nil] authorizeToken token; (protectedOriginals token)[]};
protect1:{[token;x] authorizeToken token; (protectedOriginals token)x};
protect2:{[token;x;y] authorizeToken token; (protectedOriginals token)[x;y]};
protect3:{[token;x;y;z] authorizeToken token; (protectedOriginals token)[x;y;z]};
protect4:{[token;a;b;c;d] authorizeToken token; (protectedOriginals token)[a;b;c;d]};
protect5:{[token;a;b;c;d;e] authorizeToken token; (protectedOriginals token)[a;b;c;d;e]};
protect6:{[token;a;b;c;d;e;f] authorizeToken token; (protectedOriginals token)[a;b;c;d;e;f]};
protect7:{[token;a;b;c;d;e;f;g] authorizeToken token; (protectedOriginals token)[a;b;c;d;e;f;g]};

/ Decorate a q lambda at definition time. q allows eight parameters; the projection reserves one for
/ its token, so eight-argument functions keep an explicit authorize call.
protect:{[f]
  if[0<>.z.w; '"kx.auth.protect: local calls only"];
  if[100h<>type f; '"kx.auth.protect: expects a q lambda"];
  args:(value f)1;
  arity:count args where not null args;
  if[7<arity; '"kx.auth.protect: supports functions with at most 7 arguments"];
  token:nextProtectToken;
  nextProtectToken::nextProtectToken+1;
  protectedOriginals::protectedOriginals,enlist f;
  wrapper:$[0=arity; protect0[token;];
            1=arity; protect1[token;];
            2=arity; protect2[token;;];
            3=arity; protect3[token;;;];
            4=arity; protect4[token;;;;];
            5=arity; protect5[token;;;;;];
            6=arity; protect6[token;;;;;;];
                    protect7[token;;;;;;;]];
  protectedWrappers::protectedWrappers,enlist wrapper;
  wrapper };

/ Resource paths are non-null dotted paths with no empty segment.
validDeclaredPath:{[r]
  (not null r) and all 0<count each "." vs string r };

/ True when a metadata name currently resolves to a registered protected wrapper. Historical wrappers
/ remain append-only in the registry, but do not constrain a refresh after their published binding moves.
isProtectedBinding:{[name]
  if[not -11h=type name; :0b];
  live:@[value;name;{(::)}];
  if[(::)~live; :0b];
  any live~/:protectedWrappers };

/ Resolve one aimeta row to the unique live protected wrapper it describes.
annotationRow:{[row]
  name:row`name;
  if[not -11h=type name; '"kx.auth.loadAnnotations: function name must be a symbol atom"];
  auth:row`authorize;
  if[not $[99h=type auth; all `action`resource in key auth; 0b];
    '"kx.auth.loadAnnotations: malformed @authorize metadata for ",string name];
  a:auth`action; r:auth`resource;
  if[10h=type a; a:`$a];
  if[10h=type r; r:`$r];
  if[not all -11h=type each (a;r);
    '"kx.auth.loadAnnotations: action and resource must be strings for ",string name];
  if[null a; '"kx.auth.loadAnnotations: action must not be empty for ",string name];
  if[not validDeclaredPath r; '"kx.auth.loadAnnotations: malformed resource path for ",string name];
  live:@[value;name;{(::)}];
  if[(::)~live; '"kx.auth.loadAnnotations: cannot resolve ",string name];
  hits:where live~/:protectedWrappers;
  if[1<>count hits;
    '"kx.auth.loadAnnotations: ",(string name)," is annotated but is not a .kx.auth.protect wrapper"];
  (first hits;name;a;r) };

/ Atomically replace declarations from aimeta's hydrated function model. aimeta remains optional for
/ hosts using only explicit authorize calls; protected calls fail closed until this succeeds.
loadAnnotations:{[]
  if[0<>.z.w; '"kx.auth.loadAnnotations: local calls only"];
  getter:@[value;`.aimeta.getFunctions;
    {[e] '"kx.auth.loadAnnotations: aimeta is unavailable; load and initialize kx.aimeta first"}];
  fns:@[{[g] g[]};getter;{[e] '"kx.auth.loadAnnotations: cannot read aimeta functions: ",e}];
  if[not $[0=count fns; 1b; 98h=type fns];
    '"kx.auth.loadAnnotations: aimeta returned a malformed function collection"];
  annotated:(count fns)#0b;
  if[count fns;
    if[not `name in cols fns;
      '"kx.auth.loadAnnotations: aimeta function collection has no name column"];
    annotated:$[`authorize in cols fns; 99h=type each fns`authorize; (count fns)#0b];
    missing:where (isProtectedBinding each fns`name) and not annotated;
    if[count missing;
      '"kx.auth.loadAnnotations: protected published function(s) have no @authorize declaration: ",
        ", " sv string fns[missing]`name]];
  rows:$[count fns; fns where annotated; ()];
  loaded:annotationRow each rows;
  names:$[count loaded; loaded[;1]; `symbol$()];
  tokens:$[count loaded; `long$loaded[;0]; `long$()];
  if[(count names)<>count distinct names; '"kx.auth.loadAnnotations: duplicate annotated function name"];
  if[(count tokens)<>count distinct tokens; '"kx.auth.loadAnnotations: two annotations resolve to one protected function"];
  actions:$[count loaded; `symbol$loaded[;2]; `symbol$()];
  resources:$[count loaded; `symbol$loaded[;3]; `symbol$()];
  declared::([] token:tokens; name:names; act:actions; res:resources);
  count declared };

/ ============================ login + handle lifecycle ============================
clear:{[w] bound::bound _ w; };

pwCheck:{[u;p] $[(`~svc 0)and 0=count svc 1; priorPw[u;p]; (u~svc 0)and p~svc 1]};

/ ============================ HTTP path (thin) ============================
/ The parse and the promotion are different faults and both must ANSWER (see serveHttp). .j.k's own text
/ is a position, not a diagnosis, so say what was being parsed; promote's refusal already names itself.
fromJson:{[json] promote @[.j.k; json; {[e] '"kx.auth: the x-kx-principal header is not valid JSON (",e,")"}]};

/ Authorize the HTTP caller's login, or use the explicit perimeter-trust fallback.
httpMayAssert:{[]
  if[allows[loginPrincipal .z.u; `assert; `kx.identity]; :1b];
  if[httpTrustPerimeter;
    -1 "kx.auth: WARNING asserting an HTTP principal on PERIMETER TRUST alone (login ",
       string[.z.u],", no `assert grant on `kx.identity). The network is the only control on this path.";
    :1b];
  0b };

/ A refusal must ANSWER, not signal. serveHttp wraps the host's handler, so anything it raises here is
/ raised OUTSIDE that handler's own error mapping: kdb+ would answer an authorization refusal with a bare
/ 500, and every host would have to re-wrap the module's wrapper to correct it. 403 is the honest status
/ and the module is the thing refusing, so the module answers.
refuseHttp:{[status;reason] .h.hn[status; `json; .j.j (enlist `denied)!enlist reason]};

serveHttp:{[ph;x]
  hdrs:$[1<count x; x 1; (`$())!()];
  k:key hdrs;
  / A correct proxy STRIPS any client-supplied principal header before setting its own, so exactly one
  / reaches q. Two is proof the proxy appended instead of replacing: refuse, rather than resolve by first
  / match and hand the decision to the client's forged value. q cannot verify the strip happened, but it
  / can refuse the ambiguity a missing strip produces.
  hits:where principalHeader=lower k;
  if[1<count hits;
    :refuseHttp["403 Forbidden";"denied: multiple x-kx-principal headers — the fronting proxy is not stripping the client-supplied header before setting its own"]];
  i:$[count hits; first hits; count k];
  if[i<count k;
    if[not httpMayAssert[];
      :refuseHttp["403 Forbidden";"denied: caller ",string[.z.u]," not permitted to assert identity over HTTP (grant `assert on `kx.identity, or set the perimeter-trust option)"]]];
  / fromJson is parsed INSIDE the answer boundary, after the grant check: a malformed or non-object body
  / must be ANSWERED with 400, not left to signal out of serveHttp as the bare 500 the module comment
  / above exists to prevent. `outer` (not `prior`, a reserved q keyword) saves the OUTER request's
  / principal across a call that may itself invoke serveHttp — a save/restore, not an unconditional clear,
  / so a nested request cannot clobber the identity the enclosing handler is still running under.
  p:$[i<count k; @[fromJson; hdrs k i; {[e] e}]; (::)];
  if[(i<count k) and not 99h=type p;
    :refuseHttp["400 Bad Request";"denied: x-kx-principal header refused - ",asText p]];
  outer:reqPrincipal;
  reqPrincipal::p;
  r:@[ph; x; {[outer;e] reqPrincipal::outer; 'e}[outer;]];
  reqPrincipal::outer;
  r };

configure:{[s]
  if[2<>count s; '"kx.auth.configure: expects (`user;\"password\")"];
  svc::s; svc };

/ Merge dotted claim paths for promoted fields. A path is a string; a symbol is coerced to one here,
/ because `dig` splits it with `"." vs` on every bind and a symbol would signal 'type there, far from
/ the cause. Anything else is refused by name before anything is merged, so a bad call changes nothing.
setClaims:{[d]
  if[not 99h=type d; '"kx.auth.setClaims: expects a dict, e.g. `groups`tenant!(\"realm_access.roles\";\"tenant\")"];
  v:{[k;p] $[10h=type p; p; -11h=type p; string p;
    '"kx.auth.setClaims: the path for ",string[k]," must be a string or a symbol, got type ",string type p]}'[key d; value d];
  claimPaths::claimPaths,(key d)!v; claimPaths };

/ Merge login-to-groups mappings.
setLoginGroups:{[d]
  if[not 99h=type d; '"kx.auth.setLoginGroups: expects a dict, e.g. (enlist `kxmcp)!enlist `superUsers"];
  if[not 11h=type key d; '"kx.auth.setLoginGroups: keys must be login symbols"];
  if[any null key d; '"kx.auth.setLoginGroups: login keys must not be null"];
  if[not all 11h = abs type each value d;
    '"kx.auth.setLoginGroups: values must be a symbol or a symbol vector"];
  logins::logins,d; logins };

/ Install composed qIPC authentication and handle-lifecycle callbacks.
activate:{[]
  if[active; :1b];
  priorPw::@[value;`.z.pw;{[e] {[u;p] 1b}}];
  priorPo::@[value;`.z.po;{[e] {[w] }}];
  priorPc::@[value;`.z.pc;{[e] {[w] }}];
  .z.pw:{[u;p] pwCheck[u;p]};
  .z.po:{[w] clear w; priorPo w};
  .z.pc:{[w] clear w; priorPc w};
  active::1b };

/ Install composed HTTP handlers.
activateHttp:{[]
  if[httpActive; :1b];
  priorPh::@[value;`.z.ph;{[e] {[x] }}];
  priorPp::@[value;`.z.pp;{[e] {[x] }}];
  .z.ph:{[x] serveHttp[priorPh;x]};
  .z.pp:{[x] serveHttp[priorPp;x]};
  httpActive::1b };

/ Trust HTTP assertion on the network perimeter alone. The port must be proxy-only and the proxy must
/ replace, not forward, the principal header.
setHttpTrustPerimeter:{[b]
  if[not -1h=type b; '"kx.auth.setHttpTrustPerimeter: expects a boolean"];
  httpTrustPerimeter::b;
  if[b; -1 "kx.auth: HTTP principal headers will be trusted on network perimeter alone. Ensure the port is proxy-only and the proxy STRIPS the header before setting it."];
  b };

/ ============================ perimeter gating (opt-in, coarse) ============================
/ Coarse qIPC gate: require `eval on `kx.q without interpreting the message.
gateEval:{[ph;x]
  authorize[`eval;`kx.q];
  ph x };

activatePerimeter:{[]
  if[perimeterActive; :1b];
  priorPg::@[value;`.z.pg;{[e] {[x] value x}}];
  priorPs::@[value;`.z.ps;{[e] {[x] value x}}];
  .z.pg:{[x] gateEval[priorPg;x]};
  .z.ps:{[x] gateEval[priorPs;x]};
  perimeterActive::1b };

/ ============================ public surface ============================
/ APPEND new exports. aimeta-compiled consumers may key this dict positionally, so inserting an entry would
/ change prior compiled output even though every existing name still resolves — which is why `scope` and
/ `explain` sit at the end rather than beside `authorize` where they read best.
export:`bind`current`valid`require`authorize`entitled`setPolicy`protect`loadAnnotations`configure`setClaims`setLoginGroups`setHttpTrustPerimeter`activate`activateHttp`activatePerimeter`scope`explain!(bind;current;valid;require;authorize;entitled;setPolicy;protect;loadAnnotations;configure;setClaims;setLoginGroups;setHttpTrustPerimeter;activate;activateHttp;activatePerimeter;scope;explainScope);
