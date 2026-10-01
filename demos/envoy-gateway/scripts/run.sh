#!/usr/bin/env bash
# demos/envoy-gateway/scripts/run.sh — stand up Keycloak + Envoy + a q host, drive them, assert on the outcome.
#
# The topology for INTERACTIVE HUMAN ACCESS to a kdb-x system with no MCP server in the path. The q surface
# this exercises (activateHttp, the `x-kx-principal header, httpMayAssert, setHttpTrustPerimeter,
# activatePerimeter) all shipped with the module; what this demo adds is proof against a REAL proxy, and in
# particular proof of the one defect no module code can prevent — a proxy that forgets to strip a
# client-supplied identity header.
#
# Prerequisites: Docker with the compose plugin, curl, and a kdb+ licence file. NOT a local q install and
# NOT the modules on a local module path — the q host runs in the kdbx-q image with the modules mounted
# into its module path, and the qIPC checks run inside the compose network.
#
# Usage (from the repo root):
#   bash demos/envoy-gateway/scripts/run.sh [--keep] [--verbose]
#
#   --keep      leave the stack running after the checks (for poking at it by hand)
#   --verbose   raise Envoy's log level to info, and stream q's log on failure
#
# Environment overrides:
#   KDBX_LICENSE_FILE   the licence to mount (default ~/.kx/kc.lic)
#   KDBX_Q_IMAGE        the q image (default portal.dl.kx.com/kdbx-q:5.0.20260723-rocky9-r1)
#   ENVOY_IMAGE         the proxy image (default envoyproxy/envoy:v1.31-latest — pulled on first run)
#
# Exits 0 only if every check passes. NOT wired into the default CI job: it needs Docker and an image
# pull, so it is a separate manual job rather than a tax on the five-second q smoke.

set -uo pipefail

KEEP=0
VERBOSE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO="$(cd "$HERE/.." && pwd)"
PUBLIC="$(cd "$DEMO/../.." && pwd)"
cd "$PUBLIC"

COMPOSE_FILE="demos/envoy-gateway/compose.yaml"
dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

# ── preflight ─────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the docker compose plugin is not available" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is not installed" >&2; exit 1; }

export KDBX_LICENSE_FILE="${KDBX_LICENSE_FILE:-$HOME/.kx/kc.lic}"
if [ ! -f "$KDBX_LICENSE_FILE" ]; then
  echo "no kdb+ licence at $KDBX_LICENSE_FILE" >&2
  echo "  the kdbx images take a licence only as a FILE at \$QLIC — set KDBX_LICENSE_FILE=/path/to/kc.lic" >&2
  exit 1
fi

Q_IMAGE="${KDBX_Q_IMAGE:-portal.dl.kx.com/kdbx-q:5.0.20260723-rocky9-r1}"
if ! docker image inspect "$Q_IMAGE" >/dev/null 2>&1; then
  echo "pulling the q image: $Q_IMAGE"
  if ! docker pull "$Q_IMAGE"; then
    echo "could not pull the q image: $Q_IMAGE" >&2
    echo "  docker login portal.dl.kx.com and retry, or set KDBX_Q_IMAGE to one you have." >&2
    exit 1
  fi
fi

if [ "$VERBOSE" -eq 1 ]; then export ENVOY_LOG_LEVEL=info; fi

# A previous `--keep` run leaves the stack up, and its own published ports would then read as a clash.
# Tear it down first so reruns are idempotent.
dc down -v --remove-orphans >/dev/null 2>&1 || true

# Six host ports have to be free, and one of them appears as a literal in envoy.yaml (Keycloak's, because
# the `iss` claim carries it). Check up front: a port clash otherwise surfaces as a compose networking error
# buried in the pull output, or worse as a 401 from a stranger's service on the same port.
for port in 5010 8081 9901 10000 10001 10002; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "host port $port is already in use — this demo needs 5010, 8081, 9901 and 10000-10002 free." >&2
    echo "  in use by: $(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1" (pid "$2")"}')" >&2
    exit 1
  fi
done

# ── credentials ───────────────────────────────────────────────────────────────
# Fixed demo constants, generated into a throwaway -U file below. FOUR kdb+ logins, all of which clear the
# password gate — the point being that clearing it buys nothing on its own:
#   envoyproxy   mapped to `envoyProxies  -> holds `assert on `kx.identity     (the trusted proxy)
#   operator     mapped to `qipcOperators -> holds `eval on `kx.q              (may send raw q once armed)
#   analyst      mapped to `analysts      -> holds nothing                     (may not)
#   intruder     unmapped                 -> holds nothing                     (the asserter backstop)
#   healthcheck  unmapped                 -> holds nothing                     (readiness probe only)
export DEMO_PROXY_USER=envoyproxy      DEMO_PROXY_PW=envoy-demo-pw
export DEMO_INTRUDER_USER=intruder     DEMO_INTRUDER_PW=intruder-demo-pw
export DEMO_OPERATOR_USER=operator     DEMO_OPERATOR_PW=operator-demo-pw
export DEMO_ANALYST_USER=analyst       DEMO_ANALYST_PW=analyst-demo-pw
export DEMO_HEALTH_PW=health-demo-pw
# Keycloak users, from keycloak/realm-kx.json. alice holds the realm roles trader+viewer, bob only viewer.
export KC_ALICE_USER=alice  KC_ALICE_PW=alice-demo-pw
export KC_BOB_USER=bob      KC_BOB_PW=bob-demo-pw
# 8081, not Keycloak's idiomatic 8080, because 8080 is the most contended port on a developer machine.
# Keycloak MINTS this URL in `iss`, so envoy.yaml's issuer lines have to agree — see its header comment.
export KC_ISSUER=http://localhost:8081/realms/kx
export KC_CLIENT_ID=kx-auth-cli
export GW=http://localhost:10000        # the correct gateway
export GW_FORGEABLE=http://localhost:10001   # the deliberately misconfigured one
export GW_BROWSER=http://localhost:10002     # the oauth2 redirect flow
export Q_DIRECT=http://localhost:5010        # kdb+ itself, past the proxy entirely

# macOS ships `md5`, Linux `md5sum`; take field 1, since md5sum appends the filename ("<hash>  -") while
# md5 on stdin prints the hash alone.
md5hex() { printf '%s' "$1" | { md5sum 2>/dev/null || md5; } | awk '{print $1}'; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# The work dir lives UNDER the demo directory, not in $TMPDIR. On macOS `mktemp -d` returns a /var/folders
# path that Docker Desktop does not share, and bind-mounting an unshared path silently yields an empty
# DIRECTORY at the mount target — kdb+ then reports "-U … Is a directory" and the cause is invisible. This
# directory is already inside the mount compose makes of the demo dir, so the -U file needs no mount at all.
WORK="$DEMO/.run"
rm -rf "$WORK"; mkdir -p "$WORK"
DEMO_USERPASS="$WORK/userpass"
{
  printf '%s:%s\n' "$DEMO_PROXY_USER"    "$(md5hex "$DEMO_PROXY_PW")"
  printf '%s:%s\n' "$DEMO_OPERATOR_USER" "$(md5hex "$DEMO_OPERATOR_PW")"
  printf '%s:%s\n' "$DEMO_ANALYST_USER"  "$(md5hex "$DEMO_ANALYST_PW")"
  printf '%s:%s\n' "$DEMO_INTRUDER_USER" "$(md5hex "$DEMO_INTRUDER_PW")"
  printf 'healthcheck:%s\n'              "$(md5hex "$DEMO_HEALTH_PW")"
} > "$DEMO_USERPASS"
# kdb+'s -U file is a password file, so the demo must not model one as world-readable. The image
# defaults to uid 10001, which cannot read a 0600 file this host user created on a bind mount — so
# rather than widening the file to fit the container, run the container as the user that owns it.
# Exported for compose.yaml, which defaults back to the image's own uid when these are unset.
chmod 600 "$DEMO_USERPASS"
export DEMO_RUN_UID="$(id -u)" DEMO_RUN_GID="$(id -g)"

# Envoy authenticates to q with credentials baked into envoy.yaml, because a proxy's upstream credential is
# proxy configuration. Two files therefore have to agree about a password, so assert it here rather than
# discovering the mismatch as an unexplained 401 from kdb+ halfway through the checks.
for pair in "$DEMO_PROXY_USER:$DEMO_PROXY_PW" "$DEMO_INTRUDER_USER:$DEMO_INTRUDER_PW"; do
  if ! grep -q "$(b64 "$pair")" "$DEMO/envoy/envoy.yaml"; then
    echo "envoy.yaml does not carry the Basic credential for ${pair%%:*} that run.sh generates." >&2
    echo "  expected: Basic $(b64 "$pair")" >&2
    exit 1
  fi
done

# Compose reads .env from the compose file's directory, so writing one here means every later
# `docker compose -f demos/envoy-gateway/compose.yaml …` — logs, down, exec — works with nothing exported.
# That is what makes --keep usable by hand rather than a puzzle about which variables to set.
cat > "$DEMO/.env" <<EOF
# Written by run.sh. Delete freely; it exists so ad-hoc docker compose commands work.
KDBX_LICENSE_FILE=$KDBX_LICENSE_FILE
DEMO_HEALTH_PW=$DEMO_HEALTH_PW
KDBX_Q_IMAGE=${KDBX_Q_IMAGE:-portal.dl.kx.com/kdbx-q:5.0.20260723-rocky9-r1}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.31-latest}
ENVOY_LOG_LEVEL=${ENVOY_LOG_LEVEL:-warning}
DEMO_RUN_UID=$DEMO_RUN_UID
DEMO_RUN_GID=$DEMO_RUN_GID
EOF

cleanup() {
  if [ "$KEEP" -eq 0 ]; then
    dc down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK" "$DEMO/.env"
  fi
}
trap cleanup EXIT

# ── bring the stack up ────────────────────────────────────────────────────────
echo "── starting Keycloak + Envoy + the q host (first run pulls the Envoy image) ──"
if ! dc up -d --wait --wait-timeout 120 >"$WORK/up.log" 2>&1; then
  # --wait only gates on services that DECLARE a healthcheck (here: q). Keycloak and Envoy are polled
  # below, so a failure at this point is the q host failing to load host.q at all.
  echo "the stack did not come up:" >&2
  sed 's/^/  /' "$WORK/up.log" >&2
  echo "  ── q log ──" >&2
  dc logs --no-log-prefix q 2>&1 | sed 's/^/  /' >&2
  exit 1
fi

# Readiness for the two services without container healthchecks. Poll from the host, because that is also
# the network path the checks themselves use: if the driver cannot see them, neither can the checks.
wait_for() {  # wait_for <name> <url> <expect-status>
  local name="$1" url="$2" want="$3" i code
  for i in $(seq 1 90); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null)"
    [ "$code" = "$want" ] && return 0
    sleep 1
  done
  echo "$name never became ready at $url (last status ${code:-none})" >&2
  return 1
}
wait_for "Keycloak" "$KC_ISSUER/.well-known/openid-configuration" 200 || {
  dc logs --no-log-prefix keycloak 2>&1 | tail -30 | sed 's/^/  /' >&2; exit 1; }
wait_for "Envoy" "http://localhost:9901/ready" 200 || {
  dc logs --no-log-prefix envoy 2>&1 | tail -30 | sed 's/^/  /' >&2; exit 1; }

dc logs --no-log-prefix q 2>&1 | sed 's/^/  /'
echo

# ── drive it ──────────────────────────────────────────────────────────────────
# Order matters. The HTTP checks and the CLI's login run while the qIPC perimeter is still OPEN, because
# client.q ARMS it and arming is irreversible in a live process — and the gate is coarse enough to stop
# `.kx.auth.bind` itself, which client.q then proves.
RC=0
bash "$HERE/checks.sh" || RC=$?

if [ "$RC" -eq 0 ]; then
  echo
  bash "$HERE/login-check.sh" || RC=$?
fi

if [ "$RC" -eq 0 ]; then
  echo
  # Inside the compose network, as a client that never traversed the proxy. That is the property under
  # test; the published 5010 makes the identical connection possible from outside, which is the point.
  dc exec -T \
    -e DEMO_OPERATOR_PW -e DEMO_ANALYST_PW -e DEMO_PROXY_PW \
    q q /opt/app/q-scripts/client.q -q || RC=$?
fi

# client.q armed the qIPC gate. Re-check the gateway's own route, which must be unaffected — different .z
# handler family, different opt-in.
if [ "$RC" -eq 0 ]; then
  echo
  bash "$HERE/checks.sh" --phase post || RC=$?
fi

if [ "$KEEP" -eq 1 ]; then
  cat <<EOF

stack still running (userpass $DEMO_USERPASS)
  gateway    : curl -H "Authorization: Bearer \$TOKEN" $GW/trades
  forgeable  : $GW_FORGEABLE   (no strip — identity is forgeable here, deliberately)
  browser    : open $GW_BROWSER/instruments   (Keycloak login: $KC_ALICE_USER / $KC_ALICE_PW)
  keycloak   : $KC_ISSUER  (admin console http://localhost:8081 — admin/admin)
  q direct   : q)h:hopen \`\$":localhost:5010:$DEMO_OPERATOR_USER:$DEMO_OPERATOR_PW"
  q log      : docker compose -f $COMPOSE_FILE logs -f q
  stop       : docker compose -f $COMPOSE_FILE down -v && rm -rf $WORK $DEMO/.env
EOF
elif [ "$RC" -ne 0 ] && [ "$VERBOSE" -eq 1 ]; then
  echo
  echo "── q log ──" >&2
  dc logs --no-log-prefix q 2>&1 | sed 's/^/  /' >&2
  echo "── envoy log ──" >&2
  dc logs --no-log-prefix envoy 2>&1 | tail -40 | sed 's/^/  /' >&2
fi

exit "$RC"
