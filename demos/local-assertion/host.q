/ local-assertion demo host — plain kdb+ data plus FOUR RBAC sets over ONE kx.rbac engine.
/ .
/ Loads the peer modules, logs the service account in through a standard `-U` user file, and adds a q-side
/ data gate — then layers on two more RBAC sets, so the demo shows several semantic layers all enforced
/ by one engine:
/ .
/   the data gate (a data-semantic check)      : the gated read/write verbs call
/                                                authorize[`read;`data.trades] — group x table x action.
/   the capability check (a tool-semantic check): a caller invoking a TOOL clears authorize[`query;
/                                                `kdbx.sql] first — group x capability. In a deployment
/                                                this check is made by the trusted intermediary (the MCP
/                                                container) before it ever sends a query; here the demo
/                                                makes it in a stub verb so the layer is visible.
/   the analytic check (a published operation)  : @authorize declares (`exec;`analytic), and
/                                                .kx.auth.protect enforces that metadata at runtime.
/   the assert gate (an identity check)        : bind[] consults the SAME policy for
/                                                (`assert;`kx.identity) before it will bind a principal
/                                                — WHO may assert is just another grant, not a separate
/                                                seam.
/ .
/ ONE implementation: one policy function over a combined grant table (schema grp;act;res). "data vs
/ capability vs assert" is only WHICH RESOURCE a row names. Grants diverge so the sets are visible:
/   - capability: `viewer`+`trader may `query `kdbx.sql   (both alice AND bob may invoke the tool)
/   - data      : `trader may read `data.trades`data.instruments and write `data.trades (alice only)
/ => alice clears both -> rows; bob clears the capability check (may use the tool) but the data gate
/    denies the trades data -> a clean 'denied. The two-set headline.
/ .
/ Two properties worth naming:
/   - EVERY grant is group-keyed. A kdb+ login carries no IdP groups, so the MODULE's login->groups map
/     (setLoginGroups) gives the service account some. That is an identity concern, which is why it
/     lives in kx.auth rather than as a second column in the grant tables.
/   - GRANTS ARE EXPLICIT. No verb implies another: a group that may read and write holds both rows.
/ .
/ Resource paths are DOTTED, and the `kx.* root is RESERVED for the module's own control plane
/ (`kx.identity here; `kx.rbac and `kx.q are the others). A host must not put its own resources under
/ that root — which is also why the data resources are `data.trades` / `data.instruments` rather than
/ bare table names: a host table called `identity` would otherwise collide with a control-plane
/ resource, and a data grant would confer a control-plane capability. Note the consequence — the
/ resource namespace is deliberately NOT the table namespace (see .demo.resourceOf below).
/ .
/ Run from `public/` (run.sh drives this):  q demos/local-assertion/host.q -U <userpass> -p 5011
/ Requires `kx.auth` and `kx.rbac` on the q module path.
/ NB a solitary "/" line would start a block comment — avoided throughout; and a "/" must be preceded
/ by whitespace to be a comment at all ("];/ x" is DIVIDE, not a comment).

/ --- seed data (plain kdb+ — this demo deliberately has no KDB-X module prerequisites) -------------
/ @kind data
/ @name instruments
/ @desc Instrument reference data used by the authorization demo.
/ @col sym {symbol} Instrument symbol. @attr:u
/ @col name {symbol} Display name.
/ @col sector {symbol} Market sector.
instruments:([]
  sym   :`u#`AAPL`MSFT`GOOG`AMZN`NVDA;
  name  :`Apple`Microsoft`Alphabet`Amazon`NVIDIA;
  sector:`Technology`Technology`Communication`Consumer`Technology
 );

/ @kind data
/ @name trades
/ @desc Seeded trade rows used by the protected read and analytic functions.
/ @col time {timestamp} Event time.
/ @col sym {symbol} Instrument symbol.
/ @col side {symbol} Buy or sell side.
/ @col price {float} Execution price.
/ @col size {long} Executed quantity.
trades:([]
  time : 2024.01.02D09:30:00.000000000 + 1000000000 * til 10;
  sym  : 10#`AAPL`MSFT`GOOG`AMZN`NVDA;
  side : 10#`B`S;
  price: 187.45 411.22 142.18 155.03 720.91 188.10 410.85 142.55 154.60 722.34;
  size : 100 250 75 500 40 120 300 60 450 35
 );
@[`trades;`sym;`g#];

/ --- identity assertion (the kx.auth KDB-X module) ------------------------------------------------
/ MUST assign to the global `.kx.auth` so a REMOTE caller's .kx.auth.bind / .authorize resolves.
.kx.auth:use`kx.auth;
.kx.rbac:use`kx.rbac;
.kx.aimeta:use`kx.aimeta;
/ The store location is trusted host configuration, never a remote argument. Remote administrators can
/ persist their live mutations with save[] and restore this configured snapshot with load[].
.demo.rbacStore:getenv `DEMO_RBAC_STORE;
if[0=count .demo.rbacStore; '"DEMO_RBAC_STORE is required"];
.kx.rbac.configureStore .demo.rbacStore;
/ The trusted caller connects with this service-account login. The secret is not held here —
/ run.sh starts q with `-U <userpass>` (a standard kdb+ user:md5hash file), which is the connection
/ (password) gate. WHO may then ASSERT an identity is a policy grant (below). activate[] also wires the
/ per-handle .z.po/.z.pc cleanup, and composes with the -U verifier rather than clobbering it.
.demo.svcUser:`kxmcp;
/ Groups source: leave kx.auth's DEFAULT search order (it checks the top-level `groups claim first,
/ which is what a Keycloak group-membership mapper emits). So policies key on group membership with no
/ setClaims override needed.
.kx.auth.activate[];

/ --- login groups: the service-account LOGIN's identity -------------------------------------------
/ One row, one job: identify the trusted asserter. An UNMAPPED login resolves to no groups and so
/ matches no grant — default-deny holds for every login not named here. run.sh proves that with a
/ second real login (`intruder`) whose bind is refused.
/ .
/ setLoginGroups is the local-identity sibling of setClaims. Both login and asserted principals use the
/ same promotion path, so the policy reads only p`groups.
/ Two login mappings let the demo exercise assertion and direct administration independently.
/ NB the explicit-list form on the keys. `.demo.svcUser`padmin` would be INDEXING — .demo.svcUser is a
/ variable, so juxtaposing it with a symbol literal applies it rather than building a 2-item vector.
.kx.auth.setLoginGroups[(.demo.svcUser;`padmin)!(`superUsers;`policyAdmins)];

/ --- FOUR grant SETS, ONE SCHEMA, ONE ENGINE (the point of this demo) ------------------------------
/ There is no host-written decision function any more. The grants are DECLARED through the engine's own
/ admin verbs and kx.rbac decides — group membership, exact action, segment-prefix resource cover.
/ .
/ These grant[] calls at load time ARE the reviewable, version-controlled baseline: deployment-as-code
/ with no new machinery. A kdb-format snapshot (save/load) is not diffable, so the q script stays the
/ artifact under review, and grants[] prints copy-pasteably when a live change should be promoted into it.
/ .
/ Remote mutations authorize the principal in effect for `admin on `kx.rbac. In-process calls bypass
/ the gate, which permits bootstrap.
/ DATA grants: `trader may read both tables and write `data.trades — `read stated explicitly.
.kx.rbac.grant[`trader; `read;   `data.trades];
.kx.rbac.grant[`trader; `read;   `data.instruments];
.kx.rbac.grant[`trader; `write;  `data.trades];
/ ANALYTIC grant: a higher-level published operation carries its own stable capability declaration.
.kx.rbac.grant[`trader; `exec;   `analytic];
/ CAPABILITY grants: `viewer and `trader may `query the `kdbx.sql tool capability.
.kx.rbac.grant[`viewer; `query;  `kdbx.sql];
.kx.rbac.grant[`trader; `query;  `kdbx.sql];
/ ASSERT grant: the `superUsers TIER may `assert on `kx.identity — group-keyed like the rest, reached by
/ the service-account login through the map above. A tier accumulates grants as rows, where naming a
/ group for its one capability would state the same thing twice. NB `assert dominates every other grant
/ in the thin model (an asserter can bind ANY groups), so grant it to as few logins as possible.
.kx.rbac.grant[`superUsers; `assert; `kx.identity];
/ ADMIN grant: any direct or asserted principal in `policyAdmins may change the policy.
.kx.rbac.grant[`policyAdmins; `admin; `kx.rbac];

/ Install the peer engine's scalar decision function.
.kx.auth.setPolicy .kx.rbac.policy[];

/ --- the gated verbs ------------------------------------------------------------------------------
/ Published, agent-reachable functions lead with metadata-declared authorization. protect makes the
/ check structural; loadAnnotations[] below joins each wrapper to aimeta's static requirement.
/ @kind function
/ @name .demo.getTrades
/ @desc Return trades for one instrument.
/ @public
/ @authorize read data.trades
/ @param s {symbol} Instrument symbol.
/ @returns {table} Matching trade rows.
/ @example .demo.getTrades[`AAPL]
/ @uses trades
.demo.getTrades:.kx.auth.protect {[s] select from trades where sym=s};

/ @kind function
/ @name .demo.tradeSummary
/ @desc Summarise trade count and size for one instrument.
/ @public
/ @authorize exec analytic
/ @param s {symbol} Instrument symbol.
/ @returns {table} Symbol-keyed aggregate totals.
/ @example .demo.tradeSummary[`AAPL]
/ @uses trades
.demo.tradeSummary:.kx.auth.protect {[s]
  select rows:count i,totalSize:sum size by sym from trades where sym=s};

/ Explicit checks remain first-class for internal operations and computed resources.
.demo.addTrade :{[r] .kx.auth.authorize[`write;`data.trades]; `trades insert r; count trades};
.demo.dropTrades:{[]  .kx.auth.authorize[`delete;`data.trades]; delete from `trades};

/ The capability check, made by the caller's terminus before it runs anything. Distinct from the data
/ gate above: clearing `query on `kdbx.sql says "you may use the SQL tool", not "you may read trades".
.demo.sqlTool:{[s]
  .kx.auth.authorize[`query;`kdbx.sql];        / capability: may this principal use the tool at all?
  .demo.getTrades s };                         / data: ... and may it see THIS data? (independent)

/ entitled[] is the scope-down companion: the subset of resources this principal may read, in ONE
/ round-trip. A caller uses it to present only what is visible instead of probing for denials.
/ .
/ NB the resource namespace is NOT the table namespace: a q table is `trades`, its resource is
/ `data.trades`. So this maps the process's tables into resource paths before asking. It answers in
/ resource paths, which is what a caller scoping itself down actually wants to reason about.
.demo.resourceOf:{[t] `$"data.",string t};
.demo.listTables:{[] .kx.auth.entitled[`read; .demo.resourceOf each tables[]]};

/ require[] with no action/resource decision of its own: "a valid principal must be bound". Lets a
/ caller read back the principal actually in effect on its handle — which is how client.q checks, over
/ a REAL connection, that a narrower re-bind replaced the previous principal wholesale.
.demo.whoami:{[] .kx.auth.require[]};

/ aimeta is optional for hosts that use only explicit authorize calls. This demo uses protected,
/ annotated functions, so initialize metadata after defining them and load the declaration snapshot.
.kx.aimeta.init[];
.kx.auth.loadAnnotations[];

/ --- listen ---------------------------------------------------------------------------------------
if[0=system"p"; system"p 5011"];

-1 "";
-1 "local-assertion host ready on :",(string system"p"),": identity assertion ON, FOUR RBAC sets over ONE engine";
-1 "  policy engine    : kx.rbac, installed — ",(string count .kx.rbac.grants[])," grants declared via grant[]";
-1 "  service account  : ",string[.demo.svcUser]," (login groups: superUsers, via kx.auth.setLoginGroups)";
-1 "  assert gate      : `superUsers may `assert `kx.identity (default-deny; reached via the login map)";
-1 "  capability check : groups x capability — `viewer`+`trader may `query `kdbx.sql";
-1 "  analytic check   : published @authorize — `trader may `exec `analytic";
-1 "  data gate        : groups x table x action — `trader may read `data.trades`data.instruments, write `data.trades";
-1 "  admin gate       : `policyAdmins may `admin `kx.rbac (remote-gated; local calls bypass by design)";
