#!/usr/bin/env bash
# demos/envoy-gateway/scripts/checks.sh — the HTTP half of the demo's assertions, driven with curl.
#
# Run by run.sh against the live stack, and inheriting its credentials. Every check names the property it
# pins; the section headings map onto the four constraints in kx.auth's HTTP contract.
#
# The centre of gravity is § 3. Constraint 2 — "the proxy must strip a client-supplied `x-kx-principal
# before setting its own" — is a forgeable-identity defect that NO module code can prevent, and a demo that
# only showed the happy path would teach the dangerous half. So the forgery is sent past a deliberately
# misconfigured listener and ASSERTED TO SUCCEED.
#
# Usage (from the repo root, against a stack started by run.sh):
#   bash demos/envoy-gateway/scripts/checks.sh [--phase pre|post]
#
# Two phases, because client.q ARMS the qIPC perimeter gate between them and arming cannot be undone in a
# live process. Everything below is `pre`; `post` re-checks the gateway once the gate is up.

set -uo pipefail

PHASE=pre
while [ $# -gt 0 ]; do
  case "$1" in
    --phase) PHASE="$2"; shift 2 ;;
    --phase=*) PHASE="${1#--phase=}"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done
case "$PHASE" in pre|post) ;; *) echo "unknown phase: $PHASE (want pre or post)" >&2; exit 2 ;; esac

: "${GW:?checks.sh must inherit GW from run.sh}"
: "${GW_FORGEABLE:?checks.sh must inherit GW_FORGEABLE from run.sh}"
: "${GW_BROWSER:?checks.sh must inherit GW_BROWSER from run.sh}"
: "${KC_ISSUER:?checks.sh must inherit KC_ISSUER from run.sh}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO="$(cd "$HERE/.." && pwd)"
PUBLIC="$(cd "$DEMO/../.." && pwd)"
cd "$PUBLIC"
dc() { docker compose -f "$DEMO/compose.yaml" "$@"; }

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
FAIL=0
BODY="$SCRATCH/body"

pass() { echo "  ok    $1"; }
fail() { echo "  FAIL  $1${2:+ — $2}"; [ -s "$BODY" ] && sed 's/^/          /' "$BODY"; FAIL=1; }

# GET through curl, leaving the status in $CODE and the body in $BODY. Extra args are passed to curl, so a
# check can add -H headers of its own.
get() {  # get <url> [curl args...]
  local url="$1"; shift
  CODE="$(curl -s -o "$BODY" -w '%{http_code}' --max-time 10 "$@" "$url" 2>/dev/null)"
}

body_has() { grep -qF "$1" "$BODY"; }

# Mint a real access token from Keycloak with the resource-owner password grant. The realm enables it on
# the public kx-auth-cli client purely so these checks need no browser; the device-code flow the CLI
# actually implements is exercised by login-check.sh.
token_for() {  # token_for <user> <password>
  curl -s --max-time 10 -X POST "$KC_ISSUER/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=${KC_CLIENT_ID}" \
    -d "username=$1" -d "password=$2" -d scope=openid 2>/dev/null \
    | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4
}

# Evaluate an expression on the host over raw qIPC, from inside the compose network. Used to observe q-side
# state between HTTP requests — which is the only way to see that a request-scoped identity did NOT leak.
qcall() {  # qcall <expr> [user] [password]
  local expr="$1" user="${2:-operator}" pw="${3:-${DEMO_OPERATOR_PW}}"
  dc exec -T -e DEMO_Q_EXPR="$expr" -e DEMO_Q_USER="$user" -e DEMO_Q_PW="$pw" \
    q q /opt/app/q-scripts/qcall.q -q 2>/dev/null
}

TOKEN_ALICE="$(token_for "$KC_ALICE_USER" "$KC_ALICE_PW")"
TOKEN_BOB="$(token_for "$KC_BOB_USER" "$KC_BOB_PW")"
if [ -z "$TOKEN_ALICE" ] || [ -z "$TOKEN_BOB" ]; then
  echo "  FAIL  could not mint tokens from Keycloak at $KC_ISSUER" >&2
  exit 1
fi
AUTH_ALICE=(-H "Authorization: Bearer $TOKEN_ALICE")
AUTH_BOB=(-H "Authorization: Bearer $TOKEN_BOB")
# A forged principal: a plausible header claiming a subject and a group the bearer does not have.
FORGED='{"sub":"forged","groups":["trader"]}'

# ── the post-arm phase ─────────────────────────────────────────────────────────────────────────────
# activatePerimeter[] wires .z.pg/.z.ps; activateHttp[] owns .z.ph/.z.pp. Separate opt-ins, separate handler
# families — so closing the raw-qIPC hole does NOT close the gateway's own route, which is the entire reason
# arming it is viable rather than a choice between a gateway and a boundary. Asserted through the whole
# path: Envoy validates the token, projects the principal and authorizes the route; then q asserts the
# identity and authorizes the resource.
if [ "$PHASE" = post ]; then
  echo "── after the raw-qIPC perimeter has been armed ──"
  get "$GW/trades" "${AUTH_ALICE[@]}"
  if [ "$CODE" = 200 ] && body_has '"sym":"AAPL"'; then
    pass "theGatewaysHttpPathStillServesAfterArming"
  else
    fail "theGatewaysHttpPathStillServesAfterArming" "status $CODE"
  fi
  echo
  if [ "$FAIL" -eq 0 ]; then echo "POST-ARM CHECKS PASS"; else echo "POST-ARM CHECKS FAILED" >&2; fi
  exit "$FAIL"
fi

echo "── HTTP through the gateway ──"

# ── 1. the happy path, and WHY the validator matters ────────────────────────────────────────────────
# A real Keycloak token, validated by Envoy's jwt_authn against the realm's JWKS, projected into
# `x-kx-principal, asserted by a proxy login that holds `assert on `kx.identity, and authorized by the
# host's own grants. Every layer in the topology, in one request.
get "$GW/trades" "${AUTH_ALICE[@]}"
if [ "$CODE" = 200 ] && body_has '"sym":"AAPL"'; then
  pass "proxyAssertedTraderReadsTrades"
else
  fail "proxyAssertedTraderReadsTrades" "status $CODE"
fi

# The identity in effect is the END USER, not the proxy's service login. That is the two-identities model
# working over HTTP: envoyproxy authenticated the CONNECTION, alice is the SUBJECT.
get "$GW/whoami" "${AUTH_ALICE[@]}"
if [ "$CODE" = 200 ] && body_has '"sub":"alice"' && body_has '"trader"' && ! body_has '"envoyproxy"'; then
  pass "identityInEffectIsTheEndUserNotTheProxyLogin"
else
  fail "identityInEffectIsTheEndUserNotTheProxyLogin" "status $CODE"
fi

# THE VALIDATOR, in one check. q decodes claims UNVERIFIED by design and would have accepted this happily;
# the proxy is the only thing in the path that can tell a signed token from a made-up one. Without it a
# bearer is a claims carrier, not a credential, and `kx auth login` is decoration.
get "$GW/whoami" -H "Authorization: Bearer not.a.real.token"
if [ "$CODE" = 401 ]; then
  pass "unsignedBearerIsRefusedByTheProxysValidator"
else
  fail "unsignedBearerIsRefusedByTheProxysValidator" "status $CODE, wanted 401"
fi

get "$GW/whoami"
if [ "$CODE" = 401 ]; then
  pass "requestWithNoBearerNeverReachesQ"
else
  fail "requestWithNoBearerNeverReachesQ" "status $CODE, wanted 401"
fi

# Discovery must be readable WITHOUT a token — a client cannot present a credential it has not yet been
# told how to acquire. This is the jwt_authn rule that exempts /.well-known.
get "$GW/.well-known/oauth-protected-resource"
if [ "$CODE" = 200 ] && body_has '"authorization_servers"'; then
  pass "protectedResourceMetadataIsUnauthenticated"
else
  fail "protectedResourceMetadataIsUnauthenticated" "status $CODE"
fi

# ── 2. the layering: PEP-1 relocates, PEP-2 does not ───────────────────────────────────────────────
echo
echo "── the layering (PEP-1 at the proxy, PEP-2 at the node) ──"

# The proxy refuses bob the /trades ROUTE from the verified claims. A capability decision, made without
# ever seeing the data — and q is never consulted.
get "$GW/trades" "${AUTH_BOB[@]}"
if [ "$CODE" = 403 ] && ! body_has '"denied"'; then
  pass "pep1RefusesTheRouteAtTheProxy"
else
  fail "pep1RefusesTheRouteAtTheProxy" "status $CODE (a q denial body here would mean the proxy let it through)"
fi

# The proxy ALLOWS alice the /accounts route — she is a trader, and a route is all the proxy can see. q
# refuses the RESOURCE anyway, because nobody holds `read on `data.accounts. Same status code, different
# enforcer, and the body names which: this is PEP-2 being unmovable, because only the node sees the data.
get "$GW/accounts" "${AUTH_ALICE[@]}"
if [ "$CODE" = 403 ] && body_has 'not permitted read on data.accounts'; then
  pass "pep2RefusesTheResourceAtTheNode"
else
  fail "pep2RefusesTheResourceAtTheNode" "status $CODE"
fi

# ── 3. CONSTRAINT 2: strip-then-set, or identity is forgeable ──────────────────────────────────────
echo
echo "── constraint 2: the strip-then-set trap (the appended forgery now fails closed) ──"

# On the correctly configured listener the route strips any client-supplied header before the projection
# filter adds its own, so exactly one reaches q and it is the proxy's.
get "$GW/whoami" "${AUTH_BOB[@]}" -H "x-kx-principal: $FORGED"
if [ "$CODE" = 200 ] && body_has '"sub":"bob"' && ! body_has '"forged"'; then
  pass "strippingListenerIgnoresAClientSuppliedPrincipal"
else
  fail "strippingListenerIgnoresAClientSuppliedPrincipal" "status $CODE"
fi

# ... and :10001, which omits that one line of route config, APPENDS instead of replacing — so TWO
# `x-kx-principal headers reach kdb+. That duplication is itself proof the proxy did not strip, and
# serveHttp now REFUSES it rather than resolving by first match and binding the client's forged value.
# q still cannot verify a strip happened; it can refuse the ambiguity a missing strip produces. THIS
# CHECK ASSERTS THE APPENDED FORGERY IS REFUSED.
get "$GW_FORGEABLE/whoami" "${AUTH_BOB[@]}" -H "x-kx-principal: $FORGED"
if [ "$CODE" = 403 ] && body_has 'not stripping' && ! body_has '"forged"'; then
  pass "appendedPrincipalHeaderIsRefused"
else
  fail "appendedPrincipalHeaderIsRefused" "status $CODE — expected the duplicate header to be refused"
fi

# ... so the forged group never reaches data either: the same request against /trades is refused at q
# before any authorize[] runs. The control is STILL the proxy's strip — a proxy that REPLACED the header
# with a bad value would be indistinguishable from a legitimate one — but the specific
# append-instead-of-strip misconfiguration now fails closed instead of handing identity to the client.
get "$GW_FORGEABLE/trades" "${AUTH_BOB[@]}" -H "x-kx-principal: $FORGED"
if [ "$CODE" = 403 ] && ! body_has '"sym":"AAPL"'; then
  pass "theForgedGroupNeverReachesData"
else
  fail "theForgedGroupNeverReachesData" "status $CODE — expected the appended forgery to be refused"
fi

# ── 4. CONSTRAINT 1: the proxy holds the assert grant ──────────────────────────────────────────────
echo
echo "── constraint 1: the trusted-asserter backstop, against a real proxy ──"

# Same Envoy, same validated token, same header — but this route authenticates to q as `intruder`, a login
# that clears the password gate and is not in the login map, so it holds no `assert on `kx.identity.
# serveHttp must refuse. tests/perimeter.q pins this over a synthetic header dict; here it is a real proxy
# authenticating to real kdb+ and resolving through the real login map.
get "$GW/as-intruder/whoami" "${AUTH_ALICE[@]}"
if [ "$CODE" != 200 ]; then
  pass "authenticatedButUngrantedProxyCannotAssertOverHttp"
else
  fail "authenticatedButUngrantedProxyCannotAssertOverHttp" "status $CODE — the assertion should have been refused"
fi

# ... and the refusal leaves NOTHING in effect. reqPrincipal is a process-global that current[] reads
# BEFORE the per-handle bound principal, so a leak here would cross connections, not merely requests. This
# is the live form of refusedHttpAssertLeavesNoPrincipalInEffect.
SUB="$(qcall '.kx.auth.current[]`sub')"
if [ "$SUB" = "\`operator" ]; then
  pass "refusedHttpAssertLeavesNoPrincipalInEffect"
else
  fail "refusedHttpAssertLeavesNoPrincipalInEffect" "a qIPC handle saw '$SUB', wanted \`operator"
fi

# Perimeter trust is the documented fallback for a deployment that cannot yet map the proxy's login: off by
# default, consulted only AFTER the grant, and auditing loudly on every single use. A migration crutch,
# never a destination — so the check pins the audit line, not just the success.
qcall '.demo.trustPerimeter[1b]' >/dev/null
get "$GW/as-intruder/whoami" "${AUTH_ALICE[@]}"
if [ "$CODE" = 200 ] && body_has '"sub":"alice"'; then
  pass "perimeterTrustAllowsAssertionWithoutAGrant"
else
  fail "perimeterTrustAllowsAssertionWithoutAGrant" "status $CODE"
fi
if dc logs --no-log-prefix q 2>&1 | grep -q 'PERIMETER TRUST'; then
  pass "perimeterTrustAuditsLoudlyOnEveryUse"
else
  fail "perimeterTrustAuditsLoudlyOnEveryUse" "no audit line in the q log"
fi
qcall '.demo.trustPerimeter[0b]' >/dev/null
get "$GW/as-intruder/whoami" "${AUTH_ALICE[@]}"
if [ "$CODE" != 200 ]; then
  pass "theGrantIsBackInChargeOncePerimeterTrustIsOff"
else
  fail "theGrantIsBackInChargeOncePerimeterTrustIsOff" "status $CODE"
fi

# ── 5. CONSTRAINT 4: identity is request-scoped ────────────────────────────────────────────────────
echo
echo "── constraint 4: request-scoped identity, over real sockets ──"

# Two different principals, two sequential requests, no bleed forward. Note what kdb+ actually does here:
# it answers every HTTP request with Connection: close and closes the socket, so the literal keep-alive
# reuse the contract was written against CANNOT arise on this transport. What makes the clearing
# load-bearing anyway is that reqPrincipal is a process-GLOBAL, read by current[] ahead of any per-handle
# principal — so a leak crosses connections, which is strictly worse. The next two checks pin that.
get "$GW/whoami" "${AUTH_ALICE[@]}"; ONE="$CODE:$(grep -o '"sub":"[^"]*"' "$BODY" | head -1)"
get "$GW/whoami" "${AUTH_BOB[@]}";   TWO="$CODE:$(grep -o '"sub":"[^"]*"' "$BODY" | head -1)"
if [ "$ONE" = '200:"sub":"alice"' ] && [ "$TWO" = '200:"sub":"bob"' ]; then
  pass "twoPrincipalsInSuccessionEachSeeTheirOwnIdentity"
else
  fail "twoPrincipalsInSuccessionEachSeeTheirOwnIdentity" "got $ONE then $TWO"
fi

# After a SUCCESSFUL HTTP assertion, a qIPC caller must still decide as its own login.
SUB="$(qcall '.kx.auth.current[]`sub')"
if [ "$SUB" = "\`operator" ]; then
  pass "httpIdentityDoesNotLeakOntoAQipcHandle"
else
  fail "httpIdentityDoesNotLeakOntoAQipcHandle" "a qIPC handle saw '$SUB' after an HTTP request"
fi

# ... and after a FAILING one. /boom signals a non-denial error on purpose, because serveHttp's error trap
# — the branch that clears reqPrincipal when the wrapped handler throws — is otherwise unreachable from
# outside the process. A path that throws must not be a path that leaks.
get "$GW/boom" "${AUTH_ALICE[@]}"
BOOM="$CODE"
SUB="$(qcall '.kx.auth.current[]`sub')"
if [ "$BOOM" != 200 ] && [ "$SUB" = "\`operator" ]; then
  pass "anErroringRequestLeavesNoPrincipalBehind"
else
  fail "anErroringRequestLeavesNoPrincipalBehind" "/boom gave $BOOM, a qIPC handle then saw '$SUB'"
fi

# ── 6. the browser persona ─────────────────────────────────────────────────────────────────────────
echo
echo "── the browser persona: an interactive flow q will never have ──"

# `kx auth login` implements device-code only, so without a proxy a dashboard user has no interactive flow
# at all. Envoy's oauth2 filter supplies auth-code + PKCE. Completing it needs a browser; what is asserted
# here is that the redirect is wired and points at the realm's authorization endpoint.
get "$GW_BROWSER/instruments" -o /dev/null -D "$SCRATCH/hdrs"
if { [ "$CODE" = 302 ] || [ "$CODE" = 303 ]; } && grep -qi "location:.*realms/kx/protocol/openid-connect/auth" "$SCRATCH/hdrs"; then
  pass "unauthenticatedBrowserRequestRedirectsToKeycloak"
else
  fail "unauthenticatedBrowserRequestRedirectsToKeycloak" "status $CODE"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "HTTP CHECKS PASS"; else echo "HTTP CHECKS FAILED" >&2; fi
exit "$FAIL"
