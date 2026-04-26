#!/usr/bin/env bash
# End-to-end tests for the ai-gatekeeper plugin via KBS external plugin API.
#
# Runs on the host. curl talks to KBS at localhost:8080 (port-forwarded).
# kbs-client runs inside the kbs container for attestation.
# The KBS attestation JWT is used as both Bearer and body token — no separate
# JWT signing key or test-runner service needed.
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
INITDATA_BASIC=$(cat <<'TOML'
algorithm = "sha256"
version = "0.1.0"

[data]
role = "basic"
"aa.toml" = '''
[token_configs.kbs]
url = "http://localhost:8080"
'''
"cdh.toml" = '''
socket = 'unix:///run/confidential-containers/cdh.sock'
credentials = []

[kbc]
name = "cc_kbc"
url = "http://localhost:8080"
'''
"policy.rego" = '''
'''
TOML
)
KBS_TOKEN_BASIC=$(docker compose exec -T kbs kbs-client \
    --url http://localhost:8080 \
    attest \
    --tee-key-file /opt/confidential-containers/kbs/user-keys/tee.key \
    "$INITDATA_BASIC")

echo "Obtaining KBS attestation token with premium role (initdata TOML)..."
INITDATA_PREMIUM=$(cat <<'TOML'
algorithm = "sha256"
version = "0.1.0"

[data]
role = "premium"
"aa.toml" = '''
[token_configs.kbs]
url = "http://localhost:8080"
'''
"cdh.toml" = '''
socket = 'unix:///run/confidential-containers/cdh.sock'
credentials = []

[kbc]
name = "cc_kbc"
url = "http://localhost:8080"
'''
"policy.rego" = '''
'''
TOML
)
KBS_TOKEN_PREMIUM=$(docker compose exec -T kbs kbs-client \
    --url http://localhost:8080 \
    attest \
    --tee-key-file /opt/confidential-containers/kbs/user-keys/tee.key \
    "$INITDATA_PREMIUM")

echo ""
echo "Running e2e tests against $KBS_URL"
echo ""

echo "--- basic init-data + llama-8b -> 200 ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url llama-8b)")
[[ "$status" == "200" ]] && pass "basic role accepted for llama-8b" || fail "expected 200, got $status"

# KBS normalizes all non-2xx plugin responses to 401 (per ext_plugin.md).
# Specific codes (403, 404, 400) are logged server-side and covered by unit tests.

echo "--- basic init-data + llama-70b -> 401 (plugin: 403 policy deny) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url llama-70b)")
[[ "$status" == "401" ]] && pass "basic role denied llama-70b (KBS->401)" || fail "expected 401, got $status"

echo "--- premium init-data + llama-70b -> 200 ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_PREMIUM" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_PREMIUM\"}" \
    "$(url llama-70b)")
[[ "$status" == "200" ]] && pass "premium role accepted for llama-70b" || fail "expected 200, got $status"

echo "--- unknown model -> 401 (plugin: 404) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$KBS_TOKEN_BASIC\"}" \
    "$(url unknown-model)")
[[ "$status" == "401" ]] && pass "unknown model rejected (KBS->401)" || fail "expected 401, got $status"

echo "--- missing token -> 401 (plugin: 400) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN_BASIC" \
    -H "Content-Type: application/json" \
    -d "{}" \
    "$(url llama-8b)")
[[ "$status" == "401" ]] && pass "missing token rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
