/ envoy-gateway readiness probe — the container HEALTHCHECK.
/ .
/ The kdbx-q image ships /opt/kx/bin/kdbx-healthcheck, which is the right tool for an unauthenticated
/ process. This host runs with `-U`, so an anonymous hopen is REFUSED at the password gate and that probe
/ would report a healthy process as unhealthy. So: same idea, with credentials.
/ .
/ Exits 0 when the host answers .demo.ready[] with 1b, 1 otherwise. Compose runs it as
/   q /opt/app/q-scripts/ready.q -q
/ so it needs its port and credentials from the environment rather than from argv.

port:$[count v:getenv`DEMO_Q_PORT; v; "5010"];
user:getenv`DEMO_HEALTH_USER;
pw  :getenv`DEMO_HEALTH_PW;
if[0=count user; -2 "ready.q: DEMO_HEALTH_USER is required"; exit 2];

h:@[hopen; `$":127.0.0.1:",port,":",user,":",pw; {[e] 0N}];
if[null h; exit 1];
r:@[h; ".demo.ready[]"; {[e] 0b}];
hclose h;
exit $[1b~r; 0; 1];
