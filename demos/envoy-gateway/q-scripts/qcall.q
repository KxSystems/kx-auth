/ envoy-gateway — evaluate one expression on the host over raw qIPC, from inside the compose network.
/ .
/ The shell half of the demo needs to read and change q-side state between HTTP requests: observe the
/ principal in effect on a handle that is NOT the proxy's, and flip setHttpTrustPerimeter. curl cannot do
/ either. Run by scripts/checks.sh as
/   docker compose exec -e DEMO_Q_EXPR=... -e DEMO_Q_PW=... q q /opt/app/q-scripts/qcall.q -q
/ .
/ Exits 0 and prints the result, 1 if the connection failed, 4 if the expression signalled — the same
/ "denied is not an error" split the `kx auth` CLI uses.

expr:getenv`DEMO_Q_EXPR;
if[0=count expr; -2 "qcall.q: DEMO_Q_EXPR is required"; exit 2];
port:$[count v:getenv`DEMO_Q_PORT; v; "5010"];
user:$[count v:getenv`DEMO_Q_USER; v; "operator"];
pw  :getenv`DEMO_Q_PW;

h:@[hopen; `$":127.0.0.1:",port,":",user,":",pw; {[e] 0N}];
if[null h; -2 "qcall.q: could not connect as ",user; exit 1];

r:@[h; expr; {[e] (`qcallError;e)}];
hclose h;
if[(0h=type r) and (2=count r) and `qcallError~first r; -1 "SIGNAL: ",last r; exit 4];
-1 $[10h=type r; r; -3!r];
exit 0;
