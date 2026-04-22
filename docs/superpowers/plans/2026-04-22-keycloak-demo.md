# Keycloak Demo Environment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a self-contained `demo/` directory with a Docker Compose stack that replaces the mock Keycloak in `e2e/` with a real Keycloak 26.6.1 instance, while keeping all 5 existing e2e test cases passing.

**Architecture:** A new `demo/` directory contains all files needed to stand up KBS, gRPC ai-gatekeeper plugin, OPA, and Keycloak — with no shared files from `e2e/`. Keycloak is bootstrapped via realm JSON import (`--import-realm`). The plugin connects to real Keycloak via client-credentials; a hardcoded demo secret ties the config to the realm JSON.

**Tech Stack:** Docker Compose v2, Keycloak 26.6.1 (Quarkus/UBI9), OPA 1.15.2, Python 3.12 (PyJWT), Trustee KBS (built from source), bash test script.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `demo/Dockerfile.kbs` | Create | Copy of `e2e/Dockerfile.kbs` — builds Trustee KBS with EXTERNAL_PLUGIN=true |
| `demo/Dockerfile.test-runner` | Create | Copy of `e2e/Dockerfile.test-runner` — Python image for JWT generation |
| `demo/policy.rego` | Create | Copy of `e2e/policy.rego` — role-based model access policy |
| `demo/secrets/kc-secret` | Create | Contains literal `demo-secret-change-me` |
| `demo/config/kbs.toml` | Create | Same as `e2e/config/kbs.toml` — KBS config registering ai-gatekeeper external plugin |
| `demo/config/plugin-config.yaml` | Create | Plugin config pointing at real Keycloak (`http://keycloak:8080`) |
| `demo/config/realm.json` | Create | Keycloak realm import: realm `ai-models`, client `ai-gatekeeper`, scopes `llama-8b`/`llama-70b` |
| `demo/docker-compose.yml` | Create | Full stack: setup, keycloak, opa, ai-gatekeeper, kbs, test-runner |
| `demo/tests/demo.sh` | Create | Same 5 test cases as `e2e/tests/e2e.sh`, adapted for demo directory |
| `demo/Makefile` | Create | Targets: `up`, `test`, `demo`, `down`, `logs` |
| `demo/README.md` | Create | Prerequisites, quick-start, service table, Keycloak admin console, tear-down |

---

### Task 1: Scaffold demo directory and copy static files

**Files:**
- Create: `demo/Dockerfile.kbs`
- Create: `demo/Dockerfile.test-runner`
- Create: `demo/policy.rego`
- Create: `demo/secrets/.gitkeep` (directory placeholder)
- Create: `demo/config/.gitkeep` (directory placeholder)
- Create: `demo/tests/.gitkeep` (directory placeholder)

- [ ] **Step 1: Create Dockerfile.kbs**

```
demo/Dockerfile.kbs  — exact copy of e2e/Dockerfile.kbs
```

Create `demo/Dockerfile.kbs` with this content:

```dockerfile
# Adapted from kbs/docker/Dockerfile in the trustee project.
# Changes from upstream:
#   - COPY . . replaced with git clone (different build context)
#   - EXTERNAL_PLUGIN=true added to the make invocation
#   - openssl added to runtime stage for e2e JWT generation

# rust:1.90.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c \
    AS builder
ARG ARCH=x86_64
ARG ALIYUN=false

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    gpg \
    gnupg-agent \
    git \
    sudo

RUN if [ "${ARCH}" = "aarch64" ]; then apt-get install -y libc-bin; fi

ARG DCAP_VERSION=1_25_100
RUN if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | \
    tee /etc/apt/sources.list.d/intel-sgx.list; fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libclang-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    perl \
    pkg-config \
    protobuf-compiler \
    wget \
    clang \
    cmake \
    libtss2-dev && \
    if [ "${ARCH}" = "x86_64" ]; then apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify-dev; fi

WORKDIR /usr/src/trustee
RUN git clone --depth=1 https://github.com/confidential-containers/trustee.git .

RUN cd kbs && make AS_FEATURE=coco-as-builtin EXTERNAL_PLUGIN=true ALIYUN=${ALIYUN} ARCH=${ARCH} && \
    make ARCH=${ARCH} install-kbs

RUN cargo build -p kbs-client --release && \
    install /usr/src/trustee/target/release/kbs-client /usr/local/bin/kbs-client

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9
ARG ARCH=x86_64

WORKDIR /tmp

ARG DCAP_VERSION=1_25_100
RUN apt-get update && \
    apt-get install -y \
    curl \
    gnupg \
    gnupg-agent \
    openssl && \
    if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libsgx-dcap-default-qpl \
    libsgx-dcap-quote-verify \
    libtss2-dev \
    libtss2-tctildr0 \
    libtss2-esys-3.0.2-0 ; \
    fi && \
    apt clean all && \
    rm -rf /tmp/*

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
COPY --from=builder /usr/local/bin/kbs-client /usr/local/bin/kbs-client
```

- [ ] **Step 2: Create Dockerfile.test-runner**

Create `demo/Dockerfile.test-runner`:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir 'PyJWT[crypto]' cryptography
```

- [ ] **Step 3: Create policy.rego**

Create `demo/policy.rego`:

```rego
package ai_gatekeeper

import rego.v1

default allow := false

allow if {
    allowed_models[input.claims.role][input.model]
}

allowed_models := {
    "basic":   {"llama-8b":  true},
    "premium": {"llama-8b":  true, "llama-70b": true},
}
```

- [ ] **Step 4: Verify files exist**

Run:
```bash
ls demo/Dockerfile.kbs demo/Dockerfile.test-runner demo/policy.rego
```
Expected: all three paths printed without error.

- [ ] **Step 5: Commit**

```bash
git add demo/Dockerfile.kbs demo/Dockerfile.test-runner demo/policy.rego
git commit -m "demo: add Dockerfiles and policy.rego"
```

---

### Task 2: Create secrets and config files

**Files:**
- Create: `demo/secrets/kc-secret`
- Create: `demo/config/kbs.toml`
- Create: `demo/config/plugin-config.yaml`

- [ ] **Step 1: Create kc-secret**

Create `demo/secrets/kc-secret` containing exactly (no trailing newline):

```
demo-secret-change-me
```

Verify with:
```bash
cat demo/secrets/kc-secret
```
Expected output: `demo-secret-change-me`

- [ ] **Step 2: Create kbs.toml**

Create `demo/config/kbs.toml`:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
type = "InsecureAllowAll"

[attestation_token]
insecure_key = true

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.attestation_token_broker.signer]
key_path = "/opt/confidential-containers/kbs/user-keys/token.key"
cert_path = "/opt/confidential-containers/kbs/user-keys/token-cert-chain.pem"

[attestation_service.rvps_config]
type = "BuiltIn"

[[plugins]]
name = "external"
backends = [
  { name = "ai-gatekeeper", endpoint = "http://ai-gatekeeper:50051", tls_mode = "insecure", timeout_ms = 10000 },
]
```

- [ ] **Step 3: Create plugin-config.yaml**

Create `demo/config/plugin-config.yaml`:

```yaml
jwt_verification:
  token_cert_path: /keys/plugin-token-cert.pem
  audience: ""
  leeway_seconds: 10

keycloak:
  url: http://keycloak:8080
  realm: ai-models
  client_id: ai-gatekeeper
  client_secret_path: /run/secrets/kc-secret
  timeout_seconds: 10

models:
  llama-8b:
    endpoint: https://llama-8b:8080
    scope: llama-8b
  llama-70b:
    endpoint: https://llama-70b:8080
    scope: llama-70b

opa_url: "http://opa:8181"

server:
  address: 0.0.0.0:50051
```

- [ ] **Step 4: Verify configs**

```bash
ls demo/secrets/kc-secret demo/config/kbs.toml demo/config/plugin-config.yaml
```
Expected: all three paths printed without error.

- [ ] **Step 5: Commit**

```bash
git add demo/secrets/kc-secret demo/config/kbs.toml demo/config/plugin-config.yaml
git commit -m "demo: add secrets and config files"
```

---

### Task 3: Create Keycloak realm.json

**Files:**
- Create: `demo/config/realm.json`

- [ ] **Step 1: Create realm.json**

Create `demo/config/realm.json`:

```json
{
  "id": "ai-models",
  "realm": "ai-models",
  "displayName": "AI Models",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "loginWithEmailAllowed": false,
  "bruteForceProtected": false,
  "clientScopes": [
    {
      "name": "llama-8b",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "false"
      }
    },
    {
      "name": "llama-70b",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "false"
      }
    }
  ],
  "clients": [
    {
      "clientId": "ai-gatekeeper",
      "name": "AI Gatekeeper",
      "description": "Service account for AI model access control",
      "enabled": true,
      "publicClient": false,
      "serviceAccountsEnabled": true,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "clientAuthenticatorType": "client-secret",
      "secret": "demo-secret-change-me",
      "defaultClientScopes": [],
      "optionalClientScopes": ["llama-8b", "llama-70b"]
    }
  ]
}
```

Key decisions in this JSON:
- `sslRequired: "external"` — Keycloak accepts plain HTTP inside the compose network (inter-service calls), but requires HTTPS for external clients. This is the correct setting for a containerised demo.
- `serviceAccountsEnabled: true` — required for client-credentials grant.
- `standardFlowEnabled: false` — no browser/redirect flows; service-to-service only.
- `defaultClientScopes: []` — prevents Keycloak from adding `profile`/`email`/`roles` to every token.
- `optionalClientScopes: ["llama-8b", "llama-70b"]` — the plugin requests one of these per call; Keycloak includes it in the issued token's `scope` claim.

- [ ] **Step 2: Validate JSON syntax**

```bash
python3 -m json.tool demo/config/realm.json > /dev/null && echo "JSON valid"
```
Expected: `JSON valid`

- [ ] **Step 3: Commit**

```bash
git add demo/config/realm.json
git commit -m "demo: add Keycloak realm import JSON"
```

---

### Task 4: Create docker-compose.yml

**Files:**
- Create: `demo/docker-compose.yml`

- [ ] **Step 1: Create docker-compose.yml**

Create `demo/docker-compose.yml`:

```yaml
services:
  setup:
    image: alpine/openssl
    entrypoint: /bin/ash
    command: >
      -c "
        cd /keys
        if [ ! -s token.key ]; then
          openssl genrsa -traditional -out ca.key 2048
          openssl req -new -key ca.key -out ca-req.csr -subj '/O=Demo/OU=demo/CN=demo-root'
          openssl req -x509 -days 3650 -key ca.key -in ca-req.csr -out ca-cert.pem
          openssl ecparam -name prime256v1 -genkey -noout -out token.key
          openssl req -new -key token.key -out token-req.csr -subj '/O=Demo/OU=demo/CN=demo-as'
          openssl x509 -req -in token-req.csr -CA ca-cert.pem -CAkey ca.key -CAcreateserial -out token-cert.pem
          cat token-cert.pem ca-cert.pem > token-cert-chain.pem
        fi
        if [ ! -s plugin-token.key ]; then
          openssl genrsa -out plugin-token.key 2048
          openssl req -new -x509 -key plugin-token.key -out plugin-token-cert.pem -days 365 -subj '/CN=demo-plugin'
        fi
        if [ ! -s tee.key ]; then
          openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out tee.key
        fi"
    volumes:
      - keys:/keys

  keycloak:
    image: quay.io/keycloak/keycloak:26.6.1
    command: ["start-dev", "--import-realm"]
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_HEALTH_ENABLED: "true"
    ports:
      - "8180:8080"
    volumes:
      - ./config/realm.json:/opt/keycloak/data/import/realm.json:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/realms/ai-models"]
      interval: 5s
      timeout: 5s
      retries: 30
      start_period: 30s

  opa:
    image: openpolicyagent/opa:1.15.2-static
    command:
      - run
      - --server
      - --addr
      - ":8181"
      - --log-level
      - error
      - /policy/policy.rego
    volumes:
      - ./policy.rego:/policy/policy.rego:ro
    depends_on:
      setup:
        condition: service_completed_successfully
    restart: on-failure

  ai-gatekeeper:
    build:
      context: ..
      dockerfile: Dockerfile
    ports:
      - "50051:50051"
    environment:
      AI_GATEKEEPER_CONFIG: /etc/ai-gatekeeper/config.yaml
    volumes:
      - keys:/keys:ro
      - ./config/plugin-config.yaml:/etc/ai-gatekeeper/config.yaml:ro
      - ./secrets/kc-secret:/run/secrets/kc-secret:ro
    depends_on:
      setup:
        condition: service_completed_successfully
      keycloak:
        condition: service_healthy
      opa:
        condition: service_started
    restart: on-failure

  kbs:
    build:
      context: .
      dockerfile: Dockerfile.kbs
    command:
      - /usr/local/bin/kbs
      - --config-file
      - /etc/kbs/kbs.toml
    environment:
      RUST_LOG: "${RUST_LOG:-info}"
    ports:
      - "8080:8080"
    volumes:
      - ./config/kbs.toml:/etc/kbs/kbs.toml:ro
      - keys:/opt/confidential-containers/kbs/user-keys:ro
    depends_on:
      setup:
        condition: service_completed_successfully
      ai-gatekeeper:
        condition: service_started
    restart: on-failure

  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.test-runner
    volumes:
      - keys:/keys:ro

volumes:
  keys:
```

Notes:
- `keycloak` health check hits `/realms/ai-models` — this confirms both that Keycloak is up **and** that the realm import succeeded, before `ai-gatekeeper` starts.
- `ai-gatekeeper` uses `condition: service_healthy` on `keycloak` so the plugin never attempts a token exchange against an unavailable Keycloak.
- Keycloak is exposed on host port `8180` to avoid clash with KBS on `8080`.
- `setup` does not generate `kc-secret`; the file is mounted directly from `demo/secrets/kc-secret`.

- [ ] **Step 2: Validate compose config**

```bash
cd demo && docker compose config --quiet && echo "Compose config valid" && cd ..
```
Expected: `Compose config valid` (no errors)

- [ ] **Step 3: Commit**

```bash
git add demo/docker-compose.yml
git commit -m "demo: add docker-compose.yml with real Keycloak"
```

---

### Task 5: Create test script

**Files:**
- Create: `demo/tests/demo.sh`

- [ ] **Step 1: Create demo.sh**

Create `demo/tests/demo.sh`:

```bash
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
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url llama-8b)")
[[ "$status" == "200" ]] && pass "basic role accepted for llama-8b" || fail "expected 200, got $status"

# KBS normalizes all non-2xx plugin responses to 401.
echo "--- basic + llama-70b -> 401 (plugin: 403 policy deny) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url llama-70b)")
[[ "$status" == "401" ]] && pass "basic role denied llama-70b (KBS->401)" || fail "expected 401, got $status"

echo "--- premium + llama-70b -> 200 ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_PREMIUM\"}" \
    "$(url llama-70b)")
[[ "$status" == "200" ]] && pass "premium role accepted for llama-70b" || fail "expected 200, got $status"

echo "--- unknown model -> 401 (plugin: 404) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$JWT_BASIC\"}" \
    "$(url unknown-model)")
[[ "$status" == "401" ]] && pass "unknown model rejected (KBS->401)" || fail "expected 401, got $status"

echo "--- missing token -> 401 (plugin: 400) ---"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $KBS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{}" \
    "$(url llama-8b)")
[[ "$status" == "401" ]] && pass "missing token rejected (KBS->401)" || fail "expected 401, got $status"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
```

- [ ] **Step 2: Make executable and check syntax**

```bash
chmod +x demo/tests/demo.sh
bash -n demo/tests/demo.sh && echo "Syntax OK"
```
Expected: `Syntax OK`

- [ ] **Step 3: Commit**

```bash
git add demo/tests/demo.sh
git commit -m "demo: add test script"
```

---

### Task 6: Create Makefile and README.md

**Files:**
- Create: `demo/Makefile`
- Create: `demo/README.md`

- [ ] **Step 1: Create Makefile**

Create `demo/Makefile` (use tabs for indentation — required by make):

```makefile
COMPOSE := docker compose

.PHONY: up down test demo logs

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v --remove-orphans

test:
	bash tests/demo.sh

demo:
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build
	bash tests/demo.sh; EXIT=$$?; $(COMPOSE) down -v --remove-orphans; exit $$EXIT

logs:
	$(COMPOSE) logs -f
```

- [ ] **Step 2: Create README.md**

Create `demo/README.md`:

```markdown
# AI Gatekeeper — Demo with Real Keycloak

Brings up a complete local stack: Trustee KBS, the ai-gatekeeper gRPC plugin, OPA, and a real Keycloak 26.6.1 instance — then runs the same five access-control test cases used in the e2e suite.

## Prerequisites

- Docker and Docker Compose v2 (`docker compose version`)
- `curl`, `python3` on the host (used by the test script)

## Quick Start

```bash
cd demo
make demo
```

`make demo` builds all images, starts all services, waits for KBS to become ready, runs five tests, then tears down the stack.

First run builds KBS from source (~10–20 min depending on CPU/network). Subsequent runs reuse the image cache.

## Services

| Service | Host Port | Purpose |
|---|---|---|
| `keycloak` | 8180 | Keycloak 26.6.1 — issues OIDC tokens for model scopes |
| `kbs` | 8080 | Trustee Key Broker Service — attestation and plugin proxy |
| `ai-gatekeeper` | 50051 | gRPC plugin — JWT verify, policy eval, Keycloak token exchange |
| `opa` | — | OPA server — evaluates the Rego access policy |
| `setup` | — | One-shot key generation (RSA, EC, TLS certs) |
| `test-runner` | — | Python image for one-shot JWT generation |

## Keycloak Admin Console

After `make up`, open: http://localhost:8180

Credentials: `admin` / `admin`

The `ai-models` realm and `ai-gatekeeper` client are imported automatically on first start.

## Individual Targets

```bash
make up      # Start all services in background (build first)
make test    # Run tests against a running stack
make logs    # Follow service logs
make down    # Stop and remove containers and volumes
```

## Tear Down

```bash
make down
```

Removes all containers and the `keys` volume (generated keys). The next `make up` regenerates keys from scratch.

## Demo vs e2e

`demo/` and `e2e/` are independent stacks. The difference:

| | `e2e/` | `demo/` |
|---|---|---|
| Keycloak | Python mock (returns `mock-<scope>`) | Real Keycloak 26.6.1 (full OIDC) |
| Purpose | Fast CI test — no external image pull for Keycloak | Full integration demo |

## Security Note

The Keycloak client secret (`demo-secret-change-me`) is hardcoded for demo convenience. **Do not use this configuration in production.**
```

- [ ] **Step 3: Verify Makefile syntax**

```bash
make -C demo --dry-run demo 2>&1 | head -5
```
Expected: prints the compose/bash commands that would run, no "missing separator" errors.

- [ ] **Step 4: Commit**

```bash
git add demo/Makefile demo/README.md
git commit -m "demo: add Makefile and README"
```

---

### Task 7: Smoke test — run the full demo stack

This task verifies the entire stack works end-to-end. It takes 15–30 minutes on first run (KBS builds from source).

- [ ] **Step 1: Start the stack**

```bash
cd demo
docker compose up -d --build
```

Expected: all services start. `keycloak` will take 20–30 s to pass its health check; `ai-gatekeeper` starts only after that.

- [ ] **Step 2: Watch Keycloak health**

```bash
docker compose ps
```

Wait until `keycloak` shows `healthy` status. Then check `ai-gatekeeper` and `kbs` are also up.

- [ ] **Step 3: Verify Keycloak realm imported**

```bash
curl -s http://localhost:8180/realms/ai-models | python3 -m json.tool | grep '"realm"'
```
Expected: `"realm": "ai-models"`

- [ ] **Step 4: Verify Keycloak client-credentials flow**

```bash
curl -s -X POST http://localhost:8180/realms/ai-models/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=ai-gatekeeper" \
  -d "client_secret=demo-secret-change-me" \
  -d "scope=llama-8b" | python3 -m json.tool | grep '"access_token"'
```
Expected: a line beginning with `"access_token":` containing a JWT string.

- [ ] **Step 5: Run the test suite**

```bash
bash tests/demo.sh
```

Expected output:
```
Waiting for KBS at http://localhost:8080 ...
KBS ready.
Configuring KBS resource policy...
Obtaining KBS attestation token via kbs-client...
Pre-generating plugin JWTs...

Running demo tests against http://localhost:8080 (Keycloak: real)

--- basic + llama-8b -> 200 ---
  PASS: basic role accepted for llama-8b
--- basic + llama-70b -> 401 (plugin: 403 policy deny) ---
  PASS: basic role denied llama-70b (KBS->401)
--- premium + llama-70b -> 200 ---
  PASS: premium role accepted for llama-70b
--- unknown model -> 401 (plugin: 404) ---
  PASS: unknown model rejected (KBS->401)
--- missing token -> 401 (plugin: 400) ---
  PASS: missing token rejected (KBS->401)

Results: 5 passed, 0 failed
```

- [ ] **Step 6: Tear down**

```bash
docker compose down -v --remove-orphans
cd ..
```

- [ ] **Step 7: Final commit (if any fixups were needed during smoke test)**

```bash
git add -p   # stage only intentional fixups
git commit -m "demo: fix issues found during smoke test"
```

Skip this step if no changes were needed.

---

## Self-Review

**Spec coverage:**
- [x] `demo/` is self-contained (Approach A) — all Dockerfiles copied, not referenced from `e2e/`
- [x] Keycloak 26.6.1 via realm JSON import (Approach A)
- [x] Hardcoded demo secret in `secrets/kc-secret` and `realm.json` (matching)
- [x] Same 5 test cases as `e2e/tests/e2e.sh`
- [x] Keycloak health gate before `ai-gatekeeper` starts
- [x] Admin console on 8180, KBS on 8080 — no port conflict
- [x] Makefile with `up`, `test`, `demo`, `down`, `logs`
- [x] README with prerequisites, quick-start, service table, admin console URL, tear-down, security note

**Placeholder scan:** No TBDs or TODOs.

**Type consistency:** No code types — this is infrastructure. Config keys are consistent: `client_secret_path: /run/secrets/kc-secret` in plugin-config.yaml matches mount `./secrets/kc-secret:/run/secrets/kc-secret:ro` in compose. Secret value `demo-secret-change-me` appears in both `secrets/kc-secret` and `realm.json`.
