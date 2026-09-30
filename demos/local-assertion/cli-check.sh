#!/usr/bin/env bash
# demos/local-assertion/cli-check.sh — drive a running demo host with the `kx auth` CLI.
#
# The one place the CLI meets a real q process. Its own pytest suite injects a fake pykx module, so
# nothing in it proves the qIPC handshake works against actual kdb+ — the wire types, the promotion
# readback, and the assert gate are all unverified there by construction. This closes that.
#
# AUTO-SKIPS (exit 0) unless the CLI and PyKX are both installed, because the demo's charter is to need
# nothing but a licensed q and the two modules on the module path. Install them with:
#   uv pip install -e 'packages/kx-auth-cli[qipc]'
#
# Usage (from the repo root, against a host started by run.sh):
#   bash demos/local-assertion/cli-check.sh [--port N]

set -uo pipefail

PORT="${DEMO_PORT:-5011}"
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

: "${DEMO_SVC_PW:?cli-check.sh must inherit DEMO_SVC_PW from run.sh}"
: "${DEMO_PADMIN_PW:?cli-check.sh must inherit DEMO_PADMIN_PW from run.sh}"

KX="${KX:-$(command -v kx 2>/dev/null || true)}"
if [ -z "$KX" ]; then
  echo "  skip: the kx auth CLI is not installed (uv pip install -e 'packages/kx-auth-cli[qipc]')"
  exit 0
fi
# A `kx` on PATH is not enough: a console script left behind by an earlier install points at a python
# that no longer has the package, and it fails with a traceback whose exit code is indistinguishable
# from a refusal. Demand that it actually runs, or the negative checks below would pass for the wrong
# reason — which is worse than skipping.
if ! "$KX" auth --help >/dev/null 2>&1; then
  echo "  skip: '$KX' exists but does not run — a stale console script?"
  echo "        reinstall: uv pip install -e 'packages/kx-auth-cli[qipc]'"
  exit 0
fi
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import pykx' >/dev/null 2>&1; then
  echo "  skip: PyKX is not installed, so --connect cannot run (install the [qipc] extra)"
  exit 0
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

FAIL=0
check() {  # check <name> <expected-exit> <cmd...>
  local name="$1" want="$2"; shift 2
  local rc
  # stdout and stderr are captured separately so the stable JSON envelope can be parsed strictly.
  LAST_OUT="$("$@" 2>"$SCRATCH/err")"; rc=$?
  LAST_ERR="$(cat "$SCRATCH/err")"
  if [ "$rc" -eq "$want" ]; then
    echo "  ok    $name"
  else
    echo "  FAIL  $name (exit $rc, wanted $want)"
    printf '%s\n%s\n' "$LAST_OUT" "$LAST_ERR" | sed 's/^/          /'
    FAIL=1
  fi
}

json_is() {  # json_is <name> <python expr over the `env` envelope>
  local name="$1" expr="$2"
  if printf '%s' "$LAST_OUT" | "$PY" -c "
import json,sys
env=json.load(sys.stdin)
sys.exit(0 if ($expr) else 1)
" 2>/dev/null; then
    echo "  ok    $name"
  else
    echo "  FAIL  $name"
    printf '%s\n%s\n' "$LAST_OUT" "$LAST_ERR" | sed 's/^/          /'
    FAIL=1
  fi
}

PRINCIPAL='{"sub":"alice","groups":["trader"],"jti":"unique-per-token","scope":"kdbx.read"}'

echo "── kx auth CLI, against the live host on :$PORT ──"

# The service account holds `assert on `kx.identity, so the handshake completes.
check "cliAssertBindsOverRealQipc" 0 \
  "$KX" auth assert --principal "$PRINCIPAL" --connect "localhost:$PORT" \
    --user kxmcp --password "$DEMO_SVC_PW" --json
json_is "cliReportsTheBindValid" "env['status']=='ok' and env['result']['valid'] is True"

# The readback is the payoff: `groups` was promoted by q, not by the CLI. Proving it round-trips over a
# real socket is exactly what the hermetic suite cannot do.
json_is "cliReadsBackThePromotedPrincipal" "'trader' in [str(g) for g in env['result']['promoted']['groups']]"

# A probe answers with the host's own decision, through the engine the demo installed.
check "cliProbeOfAPermittedResource" 0 \
  "$KX" auth assert --principal "$PRINCIPAL" --connect "localhost:$PORT" \
    --user kxmcp --password "$DEMO_SVC_PW" --json --probe '.kx.auth.authorize[`read;`data.trades]'

# ...and a denial is exit 4, not a stack trace the caller has to parse.
check "cliProbeOfAnUngrantedResourceIsExit4" 4 \
  "$KX" auth assert --principal "$PRINCIPAL" --connect "localhost:$PORT" \
    --user kxmcp --password "$DEMO_SVC_PW" --json --probe '.kx.auth.authorize[`read;`data.secrets]'

# The assert gate applies to the CLI like any other caller: padmin authenticates and holds
# `admin on `kx.rbac, but NOT `assert — so bind is refused, as a DENIAL (exit 4), not a generic error.
# The q-side mirror is policyAdminMayNotAssert.
#
# Both negative checks assert on the ENVELOPE, not just the exit code. Exit 1 is also what a crashed
# interpreter returns, so an exit-code-only check here would pass on a broken install and quietly stop
# testing the gate it exists to test.
check "cliCannotAssertWithoutTheAssertGrant" 4 \
  "$KX" auth assert --principal "$PRINCIPAL" --connect "localhost:$PORT" \
    --user padmin --password "$DEMO_PADMIN_PW" --json
json_is "cliRefusalIsAQDenialNotACrash" \
  "env['status']=='denied' and 'not permitted to assert' in env['reason']"

# A bad service-account password never reaches bind at all — refused at the password gate.
check "cliCannotAssertWithABadLogin" 1 \
  "$KX" auth assert --principal "$PRINCIPAL" --connect "localhost:$PORT" \
    --user kxmcp --password "wrong-pw" --json
json_is "cliBadLoginFailsAtConnectNotAtBind" \
  "env['status']=='error' and 'connect failed' in env['reason']"

# The same direct qIPC transport administers RBAC as the connecting login. An absent revoke is an
# idempotent success, but the response tells the operator that no row was removed.
check "cliRbacAbsentRevokeIsAcknowledged" 0 \
  "$KX" rbac revoke viewer read:data.missing --connect "localhost:$PORT" \
    --user padmin --password "$DEMO_PADMIN_PW" --json
json_is "cliRbacAbsentRevokeReportsNoChange" \
  "env['status']=='ok' and env['result']['changed'] is False and env['result']['acknowledgement']=='grant did not exist'"

# `show --principal` answers "what does this subject hold" through q's own `effective`, rather than
# pulling the whole table and filtering group membership client-side.
check "cliRbacShowPrincipalUsesTheEngine" 0 \
  "$KX" rbac show --principal '{"sub":"alice","groups":["trader"]}' --connect "localhost:$PORT" \
    --user padmin --password "$DEMO_PADMIN_PW" --json
json_is "cliRbacShowPrincipalReturnsOnlyThatSubjectsGrants" \
  "all(g['group']=='trader' for g in env['result']['grants']) and len(env['result']['grants'])>0"

# The lint is a separate question from the transaction guard: this policy commits fine and still has
# findings to report.
check "cliRbacVerifyReturnsFindingsAndCounts" 0 \
  "$KX" rbac verify --connect "localhost:$PORT" \
    --user padmin --password "$DEMO_PADMIN_PW" --json
json_is "cliRbacVerifyCountsBySeverity" \
  "set(env['result']['counts'])=={'error','warning','note'} and 'findings' in env['result']"

# --fail-on is exit 1, not exit 4: nothing was denied, the policy is just not in an accepted state.
# A healthy demo policy has no error-severity finding, so this must pass.
check "cliRbacVerifyFailOnErrorPassesOnAHealthyPolicy" 0 \
  "$KX" rbac verify --fail-on error --connect "localhost:$PORT" \
    --user padmin --password "$DEMO_PADMIN_PW" --json
json_is "cliRbacVerifyFailOnReportsNotFailed" \
  "env['status']=='ok' and env['result']['failed'] is False"

echo
if [ "$FAIL" -eq 0 ]; then echo "CLI CHECKS PASS"; else echo "CLI CHECKS FAILED" >&2; fi
exit "$FAIL"
