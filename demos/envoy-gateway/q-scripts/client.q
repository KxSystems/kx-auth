/ envoy-gateway demo client — CONSTRAINT 3, over raw qIPC: a proxy is a boundary only if it is the sole path.
/ .
/ Everything the other two drivers assert goes THROUGH Envoy. This one goes AROUND it. A gateway that
/ validates tokens, projects identity and authorizes routes is worth nothing if a caller can open a socket
/ to kdb+ and send q instead — and that is not a hypothetical, because kdb+ serves HTTP and qIPC ON THE SAME
/ PORT. No amount of network segmentation separates "reach /trades" from "eval arbitrary q" when both arrive
/ on 5010. A GRANT does, which is why activatePerimeter[] exists and why this demo is its first consumer.
/ .
/ Run by scripts/run.sh, inside the compose network:
/   docker compose exec -T q q /opt/app/q-scripts/client.q -q
/ so this connects on loopback to the host process in the same container. From the module's point of view
/ that is what matters: a raw qIPC connection that never traversed the proxy. The published 5010 makes the
/ identical connection possible from outside, which is exactly the hole being closed.
/ .
/ ORDER IS LOAD-BEARING. Arming the perimeter cannot be undone in a live process, and the gate is coarse
/ enough to stop `.kx.auth.bind` itself — so run.sh runs the HTTP checks and the CLI's login BEFORE this.
/ Exits 0 when every check passes, 1 if any failed.
/ NB every blank comment line carries a trailing "." — a solitary "/" would open a block comment.

/ ---- a tiny check harness (standalone — it does not load tests/test.q) ----------------------------
.c.fails:0;
.c.check:{[name;fn]
  e:@[{[g] g[]; `ok}; fn; {x}];
  $[`ok~e;
    -1 "  ok    ",string name;
    [-2 "  FAIL  ",(string name)," - ",$[10h=type e; e; -3!e]; .c.fails+:1]]; };

/ Expect a call to be refused with a 'denied that NAMES the expected gate, so a coarse perimeter refusal and
/ a fine-grained data refusal can never be conflated.
.c.deny:{[h;call;what]
  e:@[h; call; {x}];
  if[not 10h=type e; '"expected a 'denied signal, got: ",-3!e];
  if[not "denied"~6#e; '"expected 'denied, got: ",e];
  if[not count e ss what; '"denied by the wrong gate — wanted \"",what,"\", got: ",e]; };

/ ---- connect ---------------------------------------------------------------------------------------
.c.env:{[k;d] $[count v:getenv k; v; d]};
.c.port:.c.env[`DEMO_Q_PORT; "5010"];
.c.dial:{[u;pw] hopen `$":127.0.0.1:",.c.port,":",u,":",pw};

/ analyst  : mapped to `analysts, holds NOTHING — the caller the gate must stop.
/ operator : mapped to `qipcOperators, holds `eval on `kx.q — the caller it must let through.
/ envoyproxy: holds `assert on `kx.identity and NOT `eval — see theCoarseGateAlsoStopsBind below.
hAnalyst :.c.dial[.c.env[`DEMO_ANALYST_USER;  "analyst"];  .c.env[`DEMO_ANALYST_PW;  "analyst-demo-pw"]];
hOperator:.c.dial[.c.env[`DEMO_OPERATOR_USER; "operator"]; .c.env[`DEMO_OPERATOR_PW; "operator-demo-pw"]];
-1 "── raw qIPC, straight past the gateway (:",.c.port,") ──";

/ ---- 1. the bypass is real, and it is wide open ---------------------------------------------------
/ The gateway is not in this path at all. No token was validated, no route was authorized, no principal was
/ asserted — and `select from trades` reads the table, because the host's authorize[] call lives inside
/ .demo.getTrades and a raw eval simply does not go through it. Every guarantee the proxy provides is
/ conditional on this socket not being reachable.
.c.check[`rawQipcReadsDataWithNoAuthorizationAtAll; {[]
  r:hAnalyst "select from trades";
  if[not 10=count r; '"expected the bypass to read all 10 trades, got ",string count r];
  if[not `AAPL in exec sym from r; '"the bypass did not return real data"]; }]

/ An authenticated login with NO grants at all can do it. "Authenticated" was never the question.
.c.check[`theBypassNeedsNoGrantWhatsoever; {[]
  g:hAnalyst ".kx.rbac.effective[.kx.auth.current[]]";
  if[count g; '"precondition failed: analyst should hold no grants, holds ",string count g]; }]

/ ---- 2. close it -----------------------------------------------------------------------------------
/ activatePerimeter[] composes a gate onto .z.pg/.z.ps requiring `eval on `kx.q. Deliberately COARSE: it
/ does not parse the q it is gating and must not pretend to, because arbitrary q cannot be mapped honestly
/ to an (action;resource) pair and a gate that appeared to do so would be worse than none.
/ .
/ The SECOND call is the assertion. Activation verbs are idempotent by contract, and the reason is sharp: a
/ repeated call must not capture the module's OWN wrapper as its prior handler, which would compose the gate
/ with itself and gate the gate. In-process tests pin that over a fabricated .z.pg; this pins it on a live
/ process whose handlers are really wired.
.c.check[`armingThePerimeterIsIdempotent; {[]
  hOperator ".demo.armPerimeter[]";
  if[not 1b~hOperator ".demo.armPerimeter[]";
    '"a repeated activatePerimeter[] did not report already-active"]; }]

.c.check[`perimeterGateNowRefusesTheUngrantedLogin; {[]
  .c.deny[hAnalyst; "select from trades"; "eval on kx.q"]; }]

.c.check[`perimeterGateAllowsTheGrantedLogin; {[]
  r:hOperator "select from trades";
  if[not 10=count r; '"the granted operator lost its eval access, got ",-3!r]; }]

/ It is a gate, not an interpreter. The operator may send anything at all once past it.
.c.check[`perimeterGateDoesNotInspectTheQItGates; {[]
  if[not 2=hOperator "1+1"; '"the gate altered the expression it was gating"]; }]

/ TWO LAYERS, not one. The operator clears the coarse gate and the FINE-GRAINED data gate still refuses:
/ `qipcOperators holds `eval on `kx.q and no data grant, so a call through the host's gated verb is denied.
/ Reaching the process is not reading the data.
.c.check[`theResourceGateStillAppliesAfterTheCoarseOne; {[]
  .c.deny[hOperator; ".demo.getTrades[]"; "read on data.trades"]; }]

/ ---- 3. the honest consequence: the gate is coarse enough to stop the module's own verbs ----------
/ .z.pg sees every sync request, including `.kx.auth.bind`. So a trusted intermediary asserting identities
/ over qIPC needs `eval on `kx.q IN ADDITION to `assert on `kx.identity once the perimeter is armed. That is
/ not a bug — it is what "coarse" means, and a deployment that arms the gate has to grant its asserter both.
/ Worth knowing before arming it in production; the local-assertion demo's service account would stop
/ working the moment this verb was called.
.c.check[`theCoarseGateAlsoStopsBind; {[]
  hProxy:.c.dial[.c.env[`DEMO_PROXY_USER; "envoyproxy"]; .c.env[`DEMO_PROXY_PW; "envoy-demo-pw"]];
  .c.deny[hProxy; (`.kx.auth.bind; `sub`groups!(`alice; enlist `trader)); "eval on kx.q"];
  hclose hProxy; }]

/ ---- 4. and the HTTP path is untouched -------------------------------------------------------------
/ activatePerimeter[] wires .z.pg/.z.ps only; activateHttp[] owns .z.ph/.z.pp. Separate opt-ins, separate
/ handler families, so closing the qIPC hole does not close the gateway's own route — which is the entire
/ point of arming it.
/ .
/ That check lives in scripts/checks.sh, not here: run.sh calls it back as `checks.sh --phase post` once
/ this file has armed the gate. Asserting it from q needs an HTTP client that can send Basic credentials, and
/ .Q.hg takes no userinfo and no headers — but more to the point, curl proves it through the WHOLE path
/ (Envoy validates, projects and authorizes; then q asserts and authorizes) rather than just q's socket.

/ ---- report ----------------------------------------------------------------------------------------
hclose hAnalyst; hclose hOperator;
-1 "";
$[.c.fails=0;
  [-1 "QIPC CHECKS PASS"; exit 0];
  [-1 (string .c.fails)," CHECK(S) FAILED"; exit 1]];
