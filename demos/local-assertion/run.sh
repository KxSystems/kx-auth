#!/usr/bin/env bash
# demos/local-assertion/run.sh — start the host, drive it with the client, assert on the outcome.
#
# The whole demo, end to end, with no prerequisites beyond a licensed q, both modules, and aimeta on
# the module path (see modules/kx/*/docs/install.md). It proves that `kx.auth` and `kx.rbac` resolve
# through `use`; the test suite loads them flat, so run both.
#
# Usage (from the repo root):
#   bash demos/local-assertion/run.sh [--port N] [--keep]
#
#   --port N   listen on N instead of 5011
#   --keep     leave the host running after the checks (for poking at it by hand)
#
# Exits 0 only if every client check passes.

set -uo pipefail

PORT=5011
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC="$(cd "$HERE/../.." && pwd)"
cd "$PUBLIC"

Q="${Q:-$HOME/.kx/bin/q}"
[ -x "$Q" ] || Q="$(command -v q 2>/dev/null || echo q)"
command -v "$Q" >/dev/null 2>&1 || { echo "no q binary found (set Q=/path/to/q)" >&2; exit 1; }

# The module must resolve through `use` — a flat \l would not exercise the module path at all. Ask q
# rather than guessing where the module path is: the default is $HOME/.kx/mod, but $QPATH overrides it
# and a CI image can root it anywhere relative to $QHOME. Guessing a directory here fails on a
# perfectly good install.
if ! echo 'exit $[(99h=type @[use;`kx.auth;{`err}]) and (99h=type @[use;`kx.rbac;{`err}]) and 99h=type @[use;`kx.aimeta;{`err}];0;1]' | "$Q" -q >/dev/null 2>&1; then
  echo "kx.auth, kx.rbac, or kx.aimeta does not resolve through \`use\`." >&2
  echo "  Install kx.auth, kx.rbac, and aimeta on the module path: see modules/kx/auth/docs/install.md." >&2
  exit 1
fi

export DEMO_SVC_PW="s3cret-svc-pw"
export DEMO_INTRUDER_PW="s3cret-intruder-pw"
export DEMO_PADMIN_PW="s3cret-padmin-pw"
export DEMO_PORT="$PORT"

# ── the -U userpass file ──────────────────────────────────────────────────────
# Three REAL logins, all of which clear the password gate — the point being that clearing it buys
# nothing on its own:
#   kxmcp     in the login map as `superUsers   -> holds `assert on `kx.identity
#   padmin    in the login map as `policyAdmins -> holds `admin on `kx.rbac, and NOT `assert
#   intruder  not in the login map at all       -> holds nothing
# "Authenticated", "permitted to assert" and "permitted to administer the policy" are three different
# questions, and this file is what lets the demo prove it over real connections. macOS ships `md5`,
# Linux `md5sum`; take field 1, since md5sum appends the filename ("<hash>  -") while md5 on stdin
# prints the hash alone.
md5hex() { printf '%s' "$1" | { md5sum 2>/dev/null || md5; } | awk '{print $1}'; }

WORK="$(mktemp -d)"
export DEMO_RBAC_STORE="$WORK/grants"
USERPASS="$WORK/userpass"
{
  printf 'kxmcp:%s\n'    "$(md5hex "$DEMO_SVC_PW")"
  printf 'padmin:%s\n'   "$(md5hex "$DEMO_PADMIN_PW")"
  printf 'intruder:%s\n' "$(md5hex "$DEMO_INTRUDER_PW")"
} > "$USERPASS"
chmod 600 "$USERPASS"

HOST_LOG="$WORK/host.log"
HOST_PID=""
cleanup() {
  if [ -n "$HOST_PID" ] && [ "$KEEP" -eq 0 ]; then kill "$HOST_PID" 2>/dev/null || true; fi
  if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ── start the host ────────────────────────────────────────────────────────────
"$Q" demos/local-assertion/host.q -U "$USERPASS" -p "$PORT" -q < /dev/null > "$HOST_LOG" 2>&1 &
HOST_PID=$!

for _ in $(seq 1 50); do
  grep -q 'local-assertion host ready' "$HOST_LOG" 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || break
  sleep 0.2
done

if ! grep -q 'local-assertion host ready' "$HOST_LOG" 2>/dev/null; then
  echo "the host did not come up:" >&2
  cat "$HOST_LOG" >&2
  exit 1
fi
sed 's/^/  /' "$HOST_LOG"
echo

# ── drive it ──────────────────────────────────────────────────────────────────
"$Q" demos/local-assertion/client.q -q < /dev/null
RC=$?

# ── and again with the CLI ────────────────────────────────────────────────────
# Same host, same grants, a Python caller. Auto-skips unless the CLI and PyKX are installed, so the
# demo's zero-prerequisite promise holds; when they are, this is the only proof the qIPC handshake
# works against real kdb+ (the CLI's own suite fakes pykx). Only run it if the q client passed —
# otherwise the host is already suspect and a second failure adds nothing.
if [ "$RC" -eq 0 ]; then
  echo
  bash demos/local-assertion/cli-check.sh --port "$PORT" || RC=$?
fi

if [ "$KEEP" -eq 1 ]; then
  echo
  echo "host still running: pid $HOST_PID on :$PORT (userpass $USERPASS)"
  echo "  connect:  q)h:hopen \`\$\":localhost:$PORT:kxmcp:$DEMO_SVC_PW\""
  echo "  stop:     kill $HOST_PID && rm -rf $WORK"
fi

exit "$RC"
