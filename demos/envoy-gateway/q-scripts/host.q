/ envoy-gateway demo host — the SAME engine and the SAME grants as local-assertion, reached over HTTP
/ through a proxy instead of over qIPC through a trusted intermediary.
/ .
/ This is the topology for INTERACTIVE HUMAN ACCESS to a kdb-x system with no MCP server in the path. A
/ no-MCP deployment lacks two things q will never supply, and an OAuth proxy supplies both:
/ .
/   an INTERACTIVE flow : `kx auth login` implements device-code only. Envoy's oauth2 filter can run a
/                         browser redirect, so a dashboard user never touches a terminal.
/   a VALIDATOR         : bind[]/serveHttp[] decode claims UNVERIFIED by design — q does no crypto. Envoy's
/                         jwt_authn filter checks the signature against the IdP's JWKS. Without a validator
/                         somewhere in the path a bearer is a CLAIMS CARRIER, not a credential.
/ .
/ Nothing in this file is new module surface: activateHttp, the `x-kx-principal header, httpMayAssert and
/ setHttpTrustPerimeter all shipped with the module. What this demo adds is PROOF, against a real proxy.
/ .
/ THE FOUR CONSTRAINTS, and which of them q can enforce:
/ .
/   1. The proxy holds the assert grant.  ENFORCED HERE. Envoy authenticates to q with a real -U login
/      (`envoyproxy), that login resolves through setLoginGroups, and `envoyProxies holds `assert on
/      `kx.identity. Exactly the question bind[] asks over qIPC, through the same policy.
/   2. Strip-then-set, or identity is forgeable.  NOT ENFORCEABLE HERE, and that is the point. If the proxy
/      does not REMOVE a client-supplied `x-kx-principal before setting its own, a client sends the header
/      and becomes anyone. q cannot tell the forgery from the real thing; only the proxy config can. The
/      demo therefore SHOWS the forgery landing on a deliberately misconfigured listener (:10001).
/   3. A proxy is a boundary only if it is the sole path.  ENFORCED HERE, by activatePerimeter[]. Note WHY
/      it has to be: kdb+ serves HTTP and qIPC on ONE port, so no amount of network segmentation separates
/      "reach the proxy's route" from "eval arbitrary q". A grant does.
/   4. Identity is request-scoped on this path.  ENFORCED HERE. reqPrincipal is a process-global that
/      current[] reads BEFORE the per-handle bound principal, so a leak would cross connections, not merely
/      requests. serveHttp clears it after every request and on error.
/ .
/ Resource paths are DOTTED and the `kx.* root is RESERVED for the module's control plane (`kx.identity for
/ assertion, `kx.q for the perimeter gate). Host data lives under `data.*.
/ .
/ Run by scripts/run.sh via docker compose, inside the kdbx-q image:
/   q /opt/app/q-scripts/host.q -U /opt/app/.run/userpass -p 5010
/ Requires `kx.auth` and `kx.rbac` on the q module path — compose mounts them into $QHOME/mod/kx.
/ NB a solitary "/" line would start a block comment — avoided throughout; and a "/" must be preceded by
/ whitespace to be a comment at all ("];/ x" is DIVIDE, not a comment).

/ --- seed data (plain kdb+ — this demo deliberately has no KDB-X module prerequisites) -------------
instruments:([]
  sym   :`u#`AAPL`MSFT`GOOG`AMZN`NVDA;
  name  :`Apple`Microsoft`Alphabet`Amazon`NVIDIA;
  sector:`Technology`Technology`Communication`Consumer`Technology
 );

trades:([]
  time : 2024.01.02D09:30:00.000000000 + 1000000000 * til 10;
  sym  : 10#`AAPL`MSFT`GOOG`AMZN`NVDA;
  side : 10#`B`S;
  price: 187.45 411.22 142.18 155.03 720.91 188.10 410.85 142.55 154.60 722.34;
  size : 100 250 75 500 40 120 300 60 450 35
 );
@[`trades;`sym;`g#];

/ accounts exists so the LAYERING check is about authorization, not about a missing table. NOBODY is
/ granted `read on `data.accounts — see the grant block below.
accounts:([]
  account:`u#`ACME`GLOBEX`INITECH;
  owner  :`alice`bob`carol;
  balance: 1250000 830000 415000f
 );

/ --- identity assertion (the kx.auth KDB-X module) ------------------------------------------------
/ MUST assign to the global `.kx.auth` so a REMOTE caller's .kx.auth.bind / .authorize resolves by name.
.kx.auth:use`kx.auth;
.kx.rbac:use`kx.rbac;
.kx.rbac.configureStore "/tmp/kx_auth_envoy_grants";

/ Envoy connects with this login. The secret is not held here — run.sh generates a standard kdb+
/ `-U <userpass>` file and compose mounts it read-only, which is the connection (password) gate. WHO may
/ then ASSERT an identity is a policy grant, below. activate[] composes with the -U verifier rather than
/ clobbering it, and wires the per-handle .z.po/.z.pc cleanup.
.demo.proxyUser:`envoyproxy;
.kx.auth.activate[];

/ Groups source: leave kx.auth's DEFAULT search order. It checks the top-level `groups claim first and
/ then `realm_access.roles, which is what Keycloak emits for REALM ROLES with no mapper configured at all.
/ So this demo needs no setClaims call: Envoy's Lua filter projects `realm_access.roles into a `groups
/ array, and either shape would have promoted identically.

/ --- login groups: the PROXY's own identity -------------------------------------------------------
/ Four real logins clear the password gate; only two are mapped, because "authenticated" and "permitted to
/ assert" are different questions and this demo proves it over real sockets:
/   envoyproxy -> `envoyProxies   holds `assert on `kx.identity   (constraint 1)
/   operator   -> `qipcOperators  holds `eval on `kx.q            (constraint 3, the allowed side)
/   analyst    -> `analysts       holds NOTHING                   (constraint 3, the refused side)
/   intruder   -> unmapped        holds NOTHING                   (the trusted-asserter backstop)
/ NB the explicit-list form on the keys. `.demo.proxyUser`operator` would be INDEXING — .demo.proxyUser is
/ a variable, so juxtaposing it with a symbol literal applies it rather than building a 2-item vector.
.kx.auth.setLoginGroups[(.demo.proxyUser;`operator;`analyst)!(`envoyProxies;`qipcOperators;`analysts)];

/ --- grants: declared through the engine's own admin verbs ----------------------------------------
/ These grant[] calls at load time ARE the reviewable, version-controlled baseline — the same discipline
/ as local-assertion, so the two demos read as one family.
/ .
/ DATA grants, keyed on the KEYCLOAK REALM ROLES that arrive in the JWT:
.kx.rbac.grant[`trader; `read; `data.trades];
.kx.rbac.grant[`trader; `read; `data.instruments];
.kx.rbac.grant[`viewer; `read; `data.instruments];
/ ... and deliberately NO grant for `data.accounts. Envoy's RBAC filter ALLOWS the /accounts route to a
/ trader; q refuses the resource anyway. That gap is PEP-1 relocated and PEP-2 unmoved, made visible.

/ ASSERT grant: the proxy's tier may assert identity. This is what makes constraint 1 a POLICY question
/ rather than a trust-the-network assumption. NB `assert dominates every other grant in the thin model (an
/ asserter can bind ANY groups), so the tier holds this and nothing else — keeping it to control-plane
/ grants only is what makes the subject-rule fallback inert for an unbound handle.
.kx.rbac.grant[`envoyProxies; `assert; `kx.identity];

/ PERIMETER grant: who may send raw q to this process at all, once activatePerimeter[] is armed. Coarse by
/ design — it does not parse the q it is gating, because arbitrary q cannot be mapped honestly to an
/ (action;resource) pair.
.kx.rbac.grant[`qipcOperators; `eval; `kx.q];

/ POLICY ADMIN grant: Alice's `policy-admin realm role demonstrates the OAuth-aware `kx rbac --server
/ path. Bob can still inspect grants and dry-run decisions, but q refuses his mutations.
.kx.rbac.grant[`$"policy-admin"; `admin; `kx.rbac];

/ Install the peer engine's scalar decision function.
.kx.auth.setPolicy .kx.rbac.policy[];

/ --- the gated verbs ------------------------------------------------------------------------------
/ authorize[] signals 'denied on refusal and returns the principal on allow. The principal it reads is
/ whatever current[] resolves — the HTTP request principal here, a bound qIPC principal there, the
/ connecting login otherwise. Nothing below branches on which: one decision path, by invariant.
.demo.getTrades     :{[] .kx.auth.authorize[`read;`data.trades];      select from trades};
.demo.getInstruments:{[] .kx.auth.authorize[`read;`data.instruments]; select from instruments};
.demo.getAccounts   :{[] .kx.auth.authorize[`read;`data.accounts];    select from accounts};

/ require[] with no action/resource decision of its own: "a valid principal must be in effect". This is how
/ checks.sh reads back the identity the PROXY asserted, which is what makes request-scoping observable from
/ outside the process.
.demo.whoami:{[] p:.kx.auth.require[]; (`sub`groups`iss inter key p)#p};

/ --- the HTTP surface: GRANULAR NAMED ROUTES ------------------------------------------------------
/ Granular routes are the PRECONDITION for perimeter enforcement buying anything. A proxy sees method, path
/ and headers; it can relocate the CAPABILITY check ("may you reach this route") and nothing more. Front
/ this process with a single POST /query carrying arbitrary q or SQL instead, and Envoy can distinguish no
/ resources at all without parsing the body — which is a declared non-goal. Hence /trades and /instruments
/ and /accounts, not /query.
/ .
/ kdb+ hands .z.ph the path with its leading "/" already stripped and any query string still attached
/ ("trades?sym=AAPL"), and .z.pp the path and body separated by a space ("query {...}"). Take the path.
.demo.pathOf:{[s] first "?" vs first " " vs s};
.demo.requestBody:{[x] parts:" " vs x 0; $[1=count parts; ""; " " sv 1_ parts]};

/ --- the versioned RBAC gateway ------------------------------------------------------------------
/ These are fixed control-plane routes, not a general q-eval endpoint. Envoy validates the bearer and
/ serveHttp installs its promoted principal before dispatch. The q module remains the policy authority:
/ inspection is public, while apply/replace/save/load cross requireAdmin[] inside kx.rbac itself.
.demo.sym:{[x] $[10h=type x; `$x; -11h=type x; x; `$string x]};
.demo.optionalSym:{[x] $[(::)~x; `; "*"~string x; `; .demo.sym x]};
.demo.rbacPrincipal:{[body]
  p:$[(`principal in key body) and 99h=type body`principal; body`principal; .kx.auth.current[]];
  $[`groups in key p; (enlist `groups)!enlist .demo.sym each (),p`groups; p] };
/ An empty batch is a legitimate no-op patch that direct qIPC accepts, so the HTTP leg must accept it
/ too. `each` over no rows yields a GENERIC empty list, and a table built from those has untyped
/ columns that the engine rejects as non-symbol input — so type the empty case explicitly rather than
/ letting the transport disagree with qIPC about what "no operations" means.
.demo.rbacOperations:{[rows]
  if[0 = count rows; :([] op:`symbol$(); grp:`symbol$(); act:`symbol$(); res:`symbol$())];
  flip `op`grp`act`res!(.demo.sym each {x`op} each rows;
                       .demo.sym each {x`group} each rows;
                       .demo.optionalSym each {x`action} each rows;
                       .demo.optionalSym each {x`resource} each rows) };
.demo.rbacGrants:{[rows]
  if[0 = count rows; :([] grp:`symbol$(); act:`symbol$(); res:`symbol$())];
  flip `grp`act`res!(.demo.sym each {x`group} each rows;
                     .demo.optionalSym each {x`action} each rows;
                     .demo.optionalSym each {x`resource} each rows) };
.demo.rbacDry:{[body] $[`dry_run in key body; body`dry_run; 0b]};

/ JSON has neither a timestamp nor a symbol, and the seam requires an obligation to carry the SAME q type the
/ caller declared — so a transport carrying a declared context has to map values, and the mapping is contract
/ rather than detail. This mirrors what `kx rbac --ctx` does on the Python side; the two must agree.
/ `"P"$` answers 0Np for anything that is not a timestamp, which is the whole discriminator.
.demo.ctxAtom:{[v]
  $[10h=type v; [t:"P"$v; $[null t; `$v; t]];
    -9h=type v; v;
    -1h=type v; v;
    v] };
.demo.ctxValue:{[v]
  if[0h=type v; :.demo.ctxAtom each v];        / a JSON array becomes a vector of whatever its elements map to
  .demo.ctxAtom v };
.demo.rbacContext:{[body]
  if[not `context in key body; :(::)];
  c:body`context;
  if[not 99h=type c; :(::)];
  if[0=count key c; :(::)];
  (`$string key c)!.demo.ctxValue each value c };
.demo.rbacResources:{[body] .demo.sym each (),body`resources};
.demo.rbacRoute:{[path;x]
  if[path~"kx/rbac/v1/grants"; :(.j.j (enlist `result)!enlist .kx.rbac.grants[])];
  if[path~"kx/rbac/v1/verify"; :(.j.j (enlist `result)!enlist .kx.rbac.verify[])];
  body:.j.k .demo.requestBody x;
  if[path~"kx/rbac/v1/effective";
    :(.j.j (enlist `result)!enlist .kx.rbac.effective .demo.rbacPrincipal body)];
  if[path~"kx/rbac/v1/check";
    :(.j.j (enlist `result)!enlist .kx.rbac.check[.demo.rbacPrincipal body;
                                                   .demo.optionalSym body`action;
                                                   .demo.optionalSym body`resource])];
  if[path~"kx/rbac/v1/explain";
    :(.j.j (enlist `result)!enlist .kx.rbac.explain[.demo.rbacPrincipal body;
                                                     .demo.optionalSym body`action;
                                                     .demo.optionalSym body`resource])];
  / The SEAM, not the engine: only .kx.auth sees narrowing. The engine routes above stay pointed at
  / .kx.rbac so this gateway still answers grant-table questions with kx.rbac loaded alone.
  if[path~"kx/rbac/v1/scope";
    :(.j.j (enlist `result)!enlist .kx.auth.explain[.demo.rbacPrincipal body;
                                                     .demo.optionalSym body`action;
                                                     .demo.rbacResources body;
                                                     .demo.rbacContext body])];
  if[path~"kx/rbac/v1/transactions";
    :(.j.j (enlist `result)!enlist .kx.rbac.apply[.demo.rbacOperations body`operations;
                                                   .demo.rbacDry body])];
  if[path~"kx/rbac/v1/replace";
    :(.j.j (enlist `result)!enlist .kx.rbac.replace[.demo.rbacGrants body`grants;
                                                     .demo.rbacDry body])];
  if[path~"kx/rbac/v1/save"; :(.j.j (enlist `result)!enlist .kx.rbac.save[])];
  if[path~"kx/rbac/v1/load"; :(.j.j (enlist `result)!enlist .kx.rbac.load[])];
  '"no such route: ",path };

/ Route table. `boom deliberately signals a NON-denial error, because serveHttp's error path — the trap
/ that clears reqPrincipal when the wrapped handler throws — is otherwise unreachable from outside.
.demo.dispatch:{[x]
  p:.demo.pathOf x 0;
  $[p like "kx/rbac/v1/*"; .demo.rbacRoute[p;x];
    p~"trades";       .j.j .demo.getTrades[];
    p~"instruments";  .j.j .demo.getInstruments[];
    p~"accounts";     .j.j .demo.getAccounts[];
    p~"whoami";       .j.j .demo.whoami[];
    p~"boom";         '"deliberate route failure — proves serveHttp clears reqPrincipal on error too";
    '"no such route: ",p] };

/ Enlisting the body is what distinguishes "returned a string" from "signalled a string": @[f;x;{x}] hands
/ back the error text, which is type 10h, while a successful dispatch comes back as a 1-item general list.
.demo.try:{[x] enlist .demo.dispatch x};

/ A denial becomes 403 with the module's own message, so a caller sees the same reason a q caller would.
/ Anything else RE-SIGNALS, so serveHttp's error trap runs and reqPrincipal is cleared on the way out.
.demo.serve:{[x]
  r:@[.demo.try; x; {[e] e}];
  $[0h=type r;        .h.hy[`json; first r];
    "denied"~6#r;     .demo.forbidden r;
    "no such route"~13#r; .demo.notFound r;
    'r] };

.demo.body:{[status;body] "HTTP/1.1 ",status,"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ",(string count body),"\r\n\r\n",body};
.demo.forbidden:{[reason] .demo.body["403 Forbidden"; .j.j (enlist `denied)!enlist reason]};
.demo.notFound :{[reason] .demo.body["404 Not Found"; .j.j (enlist `error)!enlist reason]};

/ Define BOTH handlers BEFORE activateHttp[], so the module composes over them. activateHttp wraps the
/ PRIOR .z.ph/.z.pp; wiring them afterwards would clobber the module's wrapper and silently disable the
/ whole assertion path. NB kdb+ leaves .z.pp unset by default, so without this line POST requests would
/ reach a no-op prior handler.
.z.ph:.demo.serve;
.z.pp:.demo.serve;
.kx.auth.activateHttp[];


/ --- demo control verbs ---------------------------------------------------------------------------
/ Unguarded on purpose, and only for the checks: a real deployment arms the perimeter and decides its
/ trust posture at STARTUP, in the script under review, never over the wire. They are here because the
/ checks have to observe the process in both states within one run.
.demo.ready:{[] 1b};
.demo.armPerimeter:{[] .kx.auth.activatePerimeter[]};
.demo.trustPerimeter:{[b] .kx.auth.setHttpTrustPerimeter b};

/ --- listen ---------------------------------------------------------------------------------------
if[0=system"p"; system"p 5010"];

-1 "";
-1 "envoy-gateway host ready on :",(string system"p"),": identity asserted over HTTP by a trusted proxy";
-1 "  policy engine    : kx.rbac, installed — ",(string count .kx.rbac.grants[])," grants declared via grant[]";
-1 "  proxy login      : ",string[.demo.proxyUser]," (login groups: envoyProxies, via kx.auth.setLoginGroups)";
-1 "  assert gate      : `envoyProxies may `assert `kx.identity (default-deny; reached via the login map)";
-1 "  data gate        : `trader may read `data.trades`data.instruments; `viewer `data.instruments";
-1 "  the layering gap : NOBODY may read `data.accounts — Envoy allows the route, q refuses the resource";
-1 "  perimeter gate   : `qipcOperators may `eval `kx.q — opt-in, armed by the checks mid-run";
-1 "  HTTP routes      : /trades /instruments /accounts /whoami /boom (granular by design, not /query)";
