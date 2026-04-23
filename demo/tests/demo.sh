#!/usr/bin/env bash
# Demo end-to-end tests: real Keycloak, real KBS, real ai-gatekeeper plugin.
#
# Run from the demo/ directory (make test invokes it from there).
# curl talks to KBS at localhost:8080.
# kbs-client runs inside the kbs container for attestation.
# The KBS attestation JWT is used as both Bearer and body token — no separate
# JWT signing key needed.
set -euo pipefail

KBS_URL="${KBS_URL:-http://localhost:8080}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

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

# Attest twice with different initdata TOML blocks to produce tokens whose
# init_data_claims carry different roles in the Rego policy.
# The same JWT is used as both Bearer (KBS TEE attestation) and body token
# (plugin EAR claim normalization and role derivation).
echo "Obtaining KBS attestation token with basic role (initdata TOML)..."
KBS_TOKEN_BASIC=$(docker compose exec -T kbs kbs-client \
    --url http://localhost:8080 \
    attest \
    --tee-key-file /opt/confidential-containers/kbs/user-keys/tee.key \
    'version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = """
[token_configs.kbs]
url = "http://localhost:8080"

[extra]
role = "basic"
"""
')

echo "Obtaining KBS attestation token with premium role (initdata TOML)..."
KBS_TOKEN_PREMIUM=$(docker compose exec -T kbs kbs-client \
    --url http://localhost:8080 \
    attest \
    --tee-key-file /opt/confidential-containers/kbs/user-keys/tee.key \
    'version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = """
[token_configs.kbs]
url = "http://localhost:8080"

[extra]
role = "premium"
"""
')

echo ""
echo "Running demo tests against $KBS_URL (Keycloak: real)"
echo ""

echo "--- basic init-data + llama-8b -> 200 ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url llama-8b)")
printf "  response: %s\n" "$status"
[[ "$status" == "200" ]] && pass "basic role accepted for llama-8b" || fail "expected 200, got $status"

echo ""
# KBS normalizes all non-2xx plugin responses to 401.
echo "--- basic init-data + llama-70b -> 401 (plugin: 403 policy deny) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url llama-70b)")
printf "  response: %s\n" "$status"
[[ "$status" == "401" ]] && pass "basic role denied llama-70b (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "--- premium init-data + llama-70b -> 200 ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_PREMIUM" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_PREMIUM\"}" \
    "$(url llama-70b)")
printf "  response: %s\n" "$status"
[[ "$status" == "200" ]] && pass "premium role accepted for llama-70b" || fail "expected 200, got $status"

echo ""
echo "--- unknown model -> 401 (plugin: 404) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url unknown-model)")
printf "  response: %s\n" "$status"
[[ "$status" == "401" ]] && pass "unknown model rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "--- missing token -> 401 (plugin: 400) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{}" \
    "$(url llama-8b)")
printf "  response: %s\n" "$status"
[[ "$status" == "401" ]] && pass "missing token rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
