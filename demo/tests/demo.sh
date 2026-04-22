#!/usr/bin/env bash
# Demo end-to-end tests: real Keycloak, real KBS, real ai-gatekeeper plugin.
#
# Run from the demo/ directory (make test invokes it from there).
# curl talks to KBS at localhost:8080.
# kbs-client runs inside the kbs container for attestation.
# Plugin JWTs are generated via a one-shot docker compose run (PyJWT).
set -euo pipefail

KBS_URL="${KBS_URL:-http://localhost:8080}"
PASS=0
FAIL=0

_RESP=$(mktemp)
trap "rm -f $_RESP" EXIT

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Truncate a string to N chars with ellipsis if longer
trunc() { local s="$1" n="${2:-40}"; [[ ${#s} -gt $n ]] && printf '%s...' "${s:0:$n}" || printf '%s' "$s"; }

show_request() {
    local url="$1" body="$2"
    printf "  request:  POST %s\n" "$url"
    printf "  payload:  %s\n" "$body"
}

show_response() {
    local status="$1"
    local raw body
    raw=$(cat "$_RESP")
    if [[ "$status" == "200" ]]; then
        # KBS JWE-encrypts 200 responses with the TEE's ephemeral key.
        # Decrypt using tee.key (the private key the TEE presented during attestation).
        body=$(printf '%s' "$raw" | docker compose run --no-deps --rm -i test-runner python3 -c "
import sys, json
from jwcrypto import jwk, jwe as jwejwe
token = sys.stdin.read().strip()
key = jwk.JWK.from_pem(open('/keys/tee.key', 'rb').read())
tok = jwejwe.JWE()
tok.deserialize(token, key)
d = json.loads(tok.payload)
if 'access_token' in d and len(str(d['access_token'])) > 40:
    d['access_token'] = str(d['access_token'])[:40] + '...'
print(json.dumps(d, separators=(',', ':')))
" 2>/dev/null)
        printf "  response: %s  %s\n" "$status" "${body:-(decrypt failed)}"
    else
        body=$(printf '%s' "$raw" | python3 -c "
import sys
print(sys.stdin.read().strip() or '(empty)')
" 2>/dev/null)
        printf "  response: %s  %s\n" "$status" "${body:-(empty)}"
    fi
}

wait_for_kbs() {
    echo "Waiting for KBS at $KBS_URL ..."
    for i in $(seq 1 30); do
        if curl -s --max-time 2 -o /dev/null "$KBS_URL/kbs/v0/" 2>/dev/null; then
            echo "KBS ready."
            return
        fi
        sleep 2
    done
    echo "ERROR: KBS did not become ready within 60s" >&2
    exit 1
}

setup_policy() {
    local policy='package policy
default allow = true'
    local encoded
    encoded=$(printf '%s' "$policy" | python3 -c \
        "import sys,base64; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))")
    curl -sf -X POST \
        -H "Authorization: Bearer dev-token" \
        -H "Content-Type: application/json" \
        -d "{\"policy\": \"$encoded\"}" \
        "$KBS_URL/kbs/v0/resource-policy"
}

url() { echo "$KBS_URL/kbs/v0/external/ai-gatekeeper/models/$1"; }

wait_for_kbs
echo "Configuring KBS resource policy..."
setup_policy

echo "Obtaining KBS attestation token via kbs-client..."
KBS_TOKEN=$(docker compose exec -T kbs kbs-client \
    --url http://localhost:8080 \
    attest \
    --tee-key-file /opt/confidential-containers/kbs/user-keys/tee.key)

echo "Pre-generating plugin JWTs..."
{ read -r JWT_BASIC; read -r JWT_PREMIUM; } < <(
    docker compose run --no-deps --rm test-runner python3 -c "
import time
import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
with open('/keys/plugin-token.key', 'rb') as f:
    key = load_pem_private_key(f.read(), None)
exp = int(time.time()) + 300
for role in ['basic', 'premium']:
    print(pyjwt.encode({'role': role, 'sub': 'tee-1', 'exp': exp}, key, algorithm='RS256'))
" 2>/dev/null
)

echo ""
echo "Running demo tests against $KBS_URL (Keycloak: real)"
echo ""

echo "--- basic + llama-8b -> 200 ---"
show_request "$(url llama-8b)" "{\"token\":\"$(trunc "$JWT_BASIC")\"}"
status=$(curl -s -o "$_RESP" -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url llama-8b)")
show_response "$status"
[[ "$status" == "200" ]] && pass "basic role accepted for llama-8b" || fail "expected 200, got $status"

echo ""
# KBS normalizes all non-2xx plugin responses to 401.
echo "--- basic + llama-70b -> 401 (plugin: 403 policy deny) ---"
show_request "$(url llama-70b)" "{\"token\":\"$(trunc "$JWT_BASIC")\"}"
status=$(curl -s -o "$_RESP" -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url llama-70b)")
show_response "$status"
[[ "$status" == "401" ]] && pass "basic role denied llama-70b (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "--- premium + llama-70b -> 200 ---"
show_request "$(url llama-70b)" "{\"token\":\"$(trunc "$JWT_PREMIUM")\"}"
status=$(curl -s -o "$_RESP" -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_PREMIUM\"}" \
    "$(url llama-70b)")
show_response "$status"
[[ "$status" == "200" ]] && pass "premium role accepted for llama-70b" || fail "expected 200, got $status"

echo ""
echo "--- unknown model -> 401 (plugin: 404) ---"
show_request "$(url unknown-model)" "{\"token\":\"$(trunc "$JWT_BASIC")\"}"
status=$(curl -s -o "$_RESP" -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url unknown-model)")
show_response "$status"
[[ "$status" == "401" ]] && pass "unknown model rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "--- missing token -> 401 (plugin: 400) ---"
show_request "$(url llama-8b)" "{}"
status=$(curl -s -o "$_RESP" -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{}" \
    "$(url llama-8b)")
show_response "$status"
[[ "$status" == "401" ]] && pass "missing token rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
