#!/usr/bin/env bash
# demos/envoy-gateway/scripts/login-check.sh — the `kx auth` CLI against the gateway, the TERMINAL persona.
#
# This is the finding the topology exists to make executable: publishing RFC 9728 protected-resource
# metadata from Envoy closes the interactive-login gap with NO CODE CHANGE, because Envoy IS the resource
# server. `kx auth login --server http://localhost:10000` discovers the authorization server from a static
# JSON route and runs its device-code flow against Keycloak unchanged.
#
# Note what is deliberately NOT here: an --issuer / --authorization-server flag to skip discovery. The spec
# declines it, because it would let a caller acquire a bearer that nothing in the deployment validates —
# which invites reading a token as proof that kdb+ checked something. Prefer the topology that makes the
# existing flag correct over a flag that works without one.
#
# AUTO-SKIPS (exit 0) unless the CLI is installed, since it is an optional Python install. Install it
# with `uv tool install 'kx-auth-cli[qipc]'`, or for development with
#   uv pip install -e 'packages/kx-auth-cli[qipc]'
#
# Usage (from the repo root, against a stack started by run.sh):
#   bash demos/envoy-gateway/scripts/login-check.sh

set -uo pipefail

: "${GW:?login-check.sh must inherit GW from run.sh}"
: "${KC_ISSUER:?login-check.sh must inherit KC_ISSUER from run.sh}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO="$(cd "$HERE/.." && pwd)"
PUBLIC="$(cd "$DEMO/../.." && pwd)"
cd "$PUBLIC"

KX="${KX:-$(command -v kx 2>/dev/null || true)}"
if [ -z "$KX" ]; then
  echo "── kx auth CLI ──"
  echo "  skip: the kx auth CLI is not installed (uv pip install -e 'packages/kx-auth-cli[qipc]')"
  exit 0
fi
# A `kx` on PATH is not enough: a console script left behind by an earlier install points at a python that
# no longer has the package and fails with a traceback whose exit code is indistinguishable from a refusal.
# Demand that it actually runs, or the negative checks below would pass for the wrong reason.
if ! "$KX" auth --help >/dev/null 2>&1 || ! "$KX" rbac --help >/dev/null 2>&1; then
  echo "── kx auth CLI ──"
  echo "  skip: '$KX' exists but does not run — a stale console script?"
  echo "        reinstall: uv pip install -e 'packages/kx-auth-cli[qipc]'"
  exit 0
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
FAIL=0
# Never touch the developer's real ~/.kx/credentials.json.
export KX_AUTH_CACHE="$SCRATCH/credentials.json"
# Keycloak gates anonymous RFC 7591 dynamic client registration by default, so name the realm's public
# device-code client instead of letting the CLI register one. Supported first-class: --client-id, or this.
export KX_AUTH_CLIENT_ID=kx-auth-cli

pass() { echo "  ok    $1"; }
fail() { local detail="${2-}"; echo "  FAIL  $1${detail:+ — $detail}"; FAIL=1; }

echo "── kx auth CLI, against the gateway's RFC 9728 metadata ──"

# ── 1. discovery, exactly as the CLI performs it ───────────────────────────────────────────────────
# The CLI runs httpx with follow_redirects=False and calls raise_for_status(), so this route has to answer
# 200 at the literal path — a 301 to a trailing-slash variant is a discovery failure, not a redirect.
PRM="$(curl -s --max-time 10 -w '\n%{http_code}' "$GW/.well-known/oauth-protected-resource")"
if [ "$(printf '%s' "$PRM" | tail -1)" = 200 ] && printf '%s' "$PRM" | grep -q "$KC_ISSUER"; then
  pass "envoyPublishesProtectedResourceMetadataNamingTheRealm"
else
  fail "envoyPublishesProtectedResourceMetadataNamingTheRealm" "$(printf '%s' "$PRM" | tr '\n' ' ')"
fi

# ── 2. the device-code login, end to end ───────────────────────────────────────────────────────────
# `login` is device-code only, and a device code is approved in a BROWSER — so the automated path scripts
# Keycloak's two forms: the login page, then the OAUTH_GRANT consent page. Keycloak shows that second page
# for the device flow whatever `consentRequired` says, because approving a device is itself the consent.
#
# This is the fragile part of the demo, and knowingly so. It is pinned to keycloak:24.0 and it fails LOUDLY
# rather than skipping, because a silent skip here would stop testing the one activity this file exists for.
# Two details that are easy to get wrong: the consent form's action is RELATIVE, and it carries a hidden
# `code` field that must be posted back.
CJ="$SCRATCH/cookies"
KC_ORIGIN="${KC_ISSUER%/realms/*}"

form_action() {  # form_action <html-file> — first <form action="...">, unescaped and made absolute
  local a
  a="$(grep -o 'action="[^"]*"' "$1" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
  case "$a" in
    http://*|https://*) printf '%s' "$a" ;;
    /*)                 printf '%s%s' "$KC_ORIGIN" "$a" ;;
    *)                  printf '%s' "$a" ;;
  esac
}

hidden_value() {  # hidden_value <html-file> <input-name>
  grep -o "name=\"$2\" value=\"[^\"]*\"" "$1" | head -1 | sed 's/.*value="//; s/"$//'
}

approve_device_code() {  # approve_device_code <verification-uri-complete>
  local uri="$1" action code
  curl -s --max-time 10 -c "$CJ" -b "$CJ" -L -o "$SCRATCH/step1.html" "$uri" || return 1
  action="$(form_action "$SCRATCH/step1.html")"
  [ -n "$action" ] || return 1

  curl -s --max-time 10 -c "$CJ" -b "$CJ" -L -o "$SCRATCH/step2.html" \
    --data-urlencode "username=$KC_ALICE_USER" --data-urlencode "password=$KC_ALICE_PW" \
    "$action" || return 1

  # Already approved? Nothing more to post.
  grep -q 'name="accept"' "$SCRATCH/step2.html" || return 0
  action="$(form_action "$SCRATCH/step2.html")"
  code="$(hidden_value "$SCRATCH/step2.html" code)"
  [ -n "$action" ] && [ -n "$code" ] || return 1
  curl -s --max-time 10 -c "$CJ" -b "$CJ" -L -o "$SCRATCH/step3.html" \
    --data-urlencode "code=$code" --data 'accept=Yes' "$action" || return 1
  return 0
}

# Start the login and approve out of band. The CLI prints the verification URI to STDERR (so --json keeps
# stdout parseable), then polls the token endpoint.
( "$KX" auth login --server "$GW" --json >"$SCRATCH/login.out" 2>"$SCRATCH/login.err"; echo $? >"$SCRATCH/login.rc" ) &
LOGIN_BG=$!

URI=""
for _ in $(seq 1 40); do
  URI="$(grep -oE 'https?://[^ ]*user_code=[A-Za-z0-9-]+' "$SCRATCH/login.err" 2>/dev/null | head -1)"
  [ -n "$URI" ] && break
  kill -0 "$LOGIN_BG" 2>/dev/null || break
  sleep 0.25
done

if [ -z "$URI" ]; then
  wait "$LOGIN_BG" 2>/dev/null
  fail "cliDiscoversTheAuthorizationServerAndStartsADeviceFlow" \
    "no verification URI on stderr: $(tr '\n' ' ' <"$SCRATCH/login.err")"
else
  pass "cliDiscoversTheAuthorizationServerAndStartsADeviceFlow"
  if approve_device_code "$URI"; then
    pass "keycloakDeviceApprovalWasScriptable"
  else
    fail "keycloakDeviceApprovalWasScriptable" \
      "the login form changed shape (pinned to keycloak:24.0); HTML kept in $SCRATCH"
  fi
  # Bound the wait. The CLI polls until the device code expires — ten minutes in this realm — so an approval
  # that did not land must fail in a minute rather than hanging the whole demo behind it.
  for _ in $(seq 1 60); do [ -f "$SCRATCH/login.rc" ] && break; sleep 1; done
  if [ ! -f "$SCRATCH/login.rc" ]; then
    kill "$LOGIN_BG" 2>/dev/null
    RC=timeout
  fi
  wait "$LOGIN_BG" 2>/dev/null
  RC="${RC:-$(cat "$SCRATCH/login.rc" 2>/dev/null || echo 99)}"
  if [ "$RC" = 0 ] && grep -q '"status": *"ok"' "$SCRATCH/login.out"; then
    pass "kxAuthLoginWorksAgainstTheProxyUnchanged"
  else
    fail "kxAuthLoginWorksAgainstTheProxyUnchanged" \
      "exit $RC; out=$(tr '\n' ' ' <"$SCRATCH/login.out") err=$(tr '\n' ' ' <"$SCRATCH/login.err")"
  fi
  # The credential is cached under the literal --server string, which is what makes the proxy URL — not the
  # issuer — the thing a caller names.
  if grep -q "$GW" "$KX_AUTH_CACHE" 2>/dev/null; then
    pass "theCredentialIsCachedUnderTheProxyUrl"
  else
    fail "theCredentialIsCachedUnderTheProxyUrl"
  fi
fi

TOKEN="$(grep -o '"access_token": *"[^"]*"' "$SCRATCH/login.out" 2>/dev/null | cut -d'"' -f4)"
if [ -z "$TOKEN" ]; then
  TOKEN="$(curl -s --max-time 10 -X POST "$KC_ISSUER/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=${KC_CLIENT_ID}" \
    -d "username=$KC_ALICE_USER" -d "password=$KC_ALICE_PW" -d scope=openid \
    | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)"
fi

# ── 3. introspect as a real pre-flight ─────────────────────────────────────────────────────────────
# "Does the token the proxy will forward validate against the JWKS the proxy has configured?" — asked
# against the same JWKS URI Envoy's jwt_authn uses, so an answer here predicts the gateway's answer.
if [ -n "$TOKEN" ]; then
  if "$KX" auth introspect "$TOKEN" --jwks-uri "$KC_ISSUER/protocol/openid-connect/certs" \
       --issuer "$KC_ISSUER" --audience kdbx --json >"$SCRATCH/introspect.out" 2>/dev/null; then
    pass "introspectValidatesTheTokenAgainstTheSameJwks"
  else
    fail "introspectValidatesTheTokenAgainstTheSameJwks" "$(tr '\n' ' ' <"$SCRATCH/introspect.out")"
  fi
  # A tampered signature must not validate. This is the property q cannot check for itself, which is the
  # entire reason a validator has to exist somewhere in the path.
  if "$KX" auth introspect "${TOKEN%?}X" --jwks-uri "$KC_ISSUER/protocol/openid-connect/certs" \
       --issuer "$KC_ISSUER" --audience kdbx --json >/dev/null 2>&1; then
    fail "aTamperedTokenIsRefused" "introspect accepted a tampered signature"
  else
    pass "aTamperedTokenIsRefused"
  fi
else
  fail "introspectValidatesTheTokenAgainstTheSameJwks" "no token to introspect"
fi

# ── 4. the cached login drives the versioned RBAC gateway ──────────────────────────────────────────
if [ -s "$KX_AUTH_CACHE" ]; then
  if "$KX" rbac show --server "$GW" --json >"$SCRATCH/rbac-show.out" 2>"$SCRATCH/rbac-show.err" \
       && grep -q '"policy-admin"' "$SCRATCH/rbac-show.out"; then
    pass "kxRbacReusesTheCachedGatewayLogin"
  else
    fail "kxRbacReusesTheCachedGatewayLogin" \
      "out=$(tr '\n' ' ' <"$SCRATCH/rbac-show.out") err=$(tr '\n' ' ' <"$SCRATCH/rbac-show.err")"
  fi

  "$KX" rbac check read:data.accounts --server "$GW" --json >"$SCRATCH/rbac-denied.out" 2>/dev/null
  if [ $? -eq 4 ] && grep -q '"status": *"denied"' "$SCRATCH/rbac-denied.out"; then
    pass "kxRbacCheckMapsAPolicyDenialToExit4"
  else
    fail "kxRbacCheckMapsAPolicyDenialToExit4" "$(tr '\n' ' ' <"$SCRATCH/rbac-denied.out")"
  fi

  if "$KX" rbac grant viewer read:data.trades --server "$GW" --json >"$SCRATCH/rbac-grant.out" 2>/dev/null \
       && grep -q '"persisted": *true' "$SCRATCH/rbac-grant.out"; then
    pass "policyAdminCommitsAnAtomicGrantThroughTheGateway"
  else
    fail "policyAdminCommitsAnAtomicGrantThroughTheGateway" "$(tr '\n' ' ' <"$SCRATCH/rbac-grant.out")"
  fi
  if "$KX" rbac check read:data.trades --principal '{"sub":"bob","groups":["viewer"]}' \
       --server "$GW" --json >"$SCRATCH/rbac-allowed.out" 2>/dev/null; then
    pass "theCommittedGrantChangesTheDecisionWithoutAReload"
  else
    fail "theCommittedGrantChangesTheDecisionWithoutAReload" "$(tr '\n' ' ' <"$SCRATCH/rbac-allowed.out")"
  fi

  # The seam route, over HTTP. Many resources and a declared context both go to POST /scope, which is a
  # different route from /check — so a gateway that serves the engine but not the seam would pass every
  # check above and 404 here. The context also proves the JSON-to-q mapping agrees on both sides: the CLI
  # sends an ISO string, the gateway host turns it into a q timestamp, and the seam's type check is what
  # would refuse the pair if they ever disagreed.
  if "$KX" rbac check read data.trades --resource data.accounts \
       --principal '{"sub":"bob","groups":["viewer"]}' \
       --server "$GW" --json >"$SCRATCH/rbac-scope.out" 2>/dev/null \
       && tr -d ' \n' <"$SCRATCH/rbac-scope.out" \
            | grep -q '"obligations":{"resources":\["data.trades"\]}'; then
    pass "manyResourcesReachTheSeamThroughTheGateway"
  else
    fail "manyResourcesReachTheSeamThroughTheGateway" "$(tr '\n' ' ' <"$SCRATCH/rbac-scope.out")"
  fi

  if "$KX" rbac explain read data.trades --ctx '{"from":"2026-01-01T00:00:00"}' \
       --principal '{"sub":"bob","groups":["viewer"]}' \
       --server "$GW" --json >"$SCRATCH/rbac-ctx.out" 2>/dev/null \
       && grep -q '"declared"' "$SCRATCH/rbac-ctx.out"; then
    pass "aDeclaredContextSurvivesTheGatewaysJsonRoundTrip"
  else
    fail "aDeclaredContextSurvivesTheGatewaysJsonRoundTrip" "$(tr '\n' ' ' <"$SCRATCH/rbac-ctx.out")"
  fi
  # The two read-only verbs added on top of the same versioned route set. `show --principal` reaches
  # POST /kx/rbac/v1/effective, which is q's own group matching rather than client-side filtering.
  if "$KX" rbac show --principal '{"sub":"bob","groups":["viewer"]}' --server "$GW" --json \
       >"$SCRATCH/rbac-eff.out" 2>/dev/null \
       && grep -q '"viewer"' "$SCRATCH/rbac-eff.out" && ! grep -q '"policy-admin"' "$SCRATCH/rbac-eff.out"; then
    pass "kxRbacShowPrincipalReachesEffectiveThroughTheGateway"
  else
    fail "kxRbacShowPrincipalReachesEffectiveThroughTheGateway" "$(tr '\n' ' ' <"$SCRATCH/rbac-eff.out")"
  fi

  # GET /kx/rbac/v1/verify. The demo policy is healthy, so --fail-on error must exit 0; a tripped lint
  # would be exit 1, never exit 4, because nothing was denied.
  if "$KX" rbac verify --fail-on error --server "$GW" --json >"$SCRATCH/rbac-verify.out" 2>/dev/null \
       && grep -q '"failed": *false' "$SCRATCH/rbac-verify.out" \
       && grep -q '"counts"' "$SCRATCH/rbac-verify.out"; then
    pass "kxRbacVerifyLintsThePolicyThroughTheGateway"
  else
    fail "kxRbacVerifyLintsThePolicyThroughTheGateway" "$(tr '\n' ' ' <"$SCRATCH/rbac-verify.out")"
  fi

  # An EMPTY operations batch. Direct qIPC accepts it as a no-op patch, so the gateway must too — a
  # retry loop that has already applied everything sends exactly this, and a transport that rejected it
  # would turn a successful retry into a spurious failure.
  printf '{"operations": []}\n' >"$SCRATCH/empty-ops.json"
  if "$KX" rbac import "$SCRATCH/empty-ops.json" --server "$GW" --json >"$SCRATCH/rbac-empty.out" 2>/dev/null \
       && grep -q '"changed": *false' "$SCRATCH/rbac-empty.out"; then
    pass "anEmptyOperationBatchIsANoOpOverTheGateway"
  else
    fail "anEmptyOperationBatchIsANoOpOverTheGateway" "$(tr '\n' ' ' <"$SCRATCH/rbac-empty.out")"
  fi

  # Restore the reviewable baseline before the remaining demo checks.
  "$KX" rbac revoke viewer read:data.trades --server "$GW" --json >/dev/null 2>&1 || \
    fail "theGatewayGrantWasReverted" "revoke failed"

  TOKEN_BOB="$(curl -s --max-time 10 -X POST "$KC_ISSUER/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=${KC_CLIENT_ID}" \
    -d "username=$KC_BOB_USER" -d "password=$KC_BOB_PW" -d scope=openid \
    | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)"
  if "$KX" rbac show --server "$GW" --token "$TOKEN_BOB" --json >/dev/null 2>&1; then
    pass "aNonAdminCanInspectThePublicGrantSet"
  else
    fail "aNonAdminCanInspectThePublicGrantSet"
  fi
  "$KX" rbac grant viewer read:data.trades --server "$GW" --token "$TOKEN_BOB" --json \
    >"$SCRATCH/rbac-bob.out" 2>/dev/null
  if [ $? -eq 4 ]; then
    pass "aNonAdminCannotMutateThePolicy"
  else
    fail "aNonAdminCannotMutateThePolicy" "$(tr '\n' ' ' <"$SCRATCH/rbac-bob.out")"
  fi
else
  fail "kxRbacReusesTheCachedGatewayLogin" "login did not produce a cache entry"
fi

# ── 5. the qIPC leg decides the same way the proxy leg does ─────────────────────────────────────────
# The CLI's projection carries the raw claims and lets q promote them, so `groups` here comes from
# realm_access.roles through kx.auth's DEFAULT search order — no setClaims, no mapper, no Python-side
# promotion. Note the subject differs from the HTTP leg by design: Envoy's Lua projects
# preferred_username, the CLI projects the token's `sub` (a Keycloak UUID). The DECISION keys on groups, so
# both legs decide identically — which is the parity worth asserting.
if ! python3 -c 'import pykx' >/dev/null 2>&1; then
  echo "  skip: PyKX is not installed, so --connect cannot run (install the [qipc] extra)"
elif [ -n "$TOKEN" ]; then
  if "$KX" auth assert --token "$TOKEN" --connect "localhost:5010" \
       --user "${DEMO_PROXY_USER:-envoyproxy}" --password "${DEMO_PROXY_PW:-envoy-demo-pw}" --json \
       --probe '.kx.auth.authorize[`read;`data.trades]' >"$SCRATCH/assert.out" 2>/dev/null; then
    pass "theSameTokenIsAllowedOverQipcAsOverHttp"
  else
    fail "theSameTokenIsAllowedOverQipcAsOverHttp" "$(tr '\n' ' ' <"$SCRATCH/assert.out")"
  fi
  # ... and refused for the same resource the HTTP leg refused, with the CLI's exit code 4 for "denied"
  # rather than a stack trace. Same policy, two transports, one decision path.
  "$KX" auth assert --token "$TOKEN" --connect "localhost:5010" \
    --user "${DEMO_PROXY_USER:-envoyproxy}" --password "${DEMO_PROXY_PW:-envoy-demo-pw}" --json \
    --probe '.kx.auth.authorize[`read;`data.accounts]' >"$SCRATCH/denied.out" 2>/dev/null
  if [ $? -eq 4 ]; then
    pass "theSameResourceIsDeniedOverQipcWithExitCode4"
  else
    fail "theSameResourceIsDeniedOverQipcWithExitCode4" "$(tr '\n' ' ' <"$SCRATCH/denied.out")"
  fi
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "CLI CHECKS PASS"; else echo "CLI CHECKS FAILED" >&2; fi
exit "$FAIL"
