# Demo Model Endpoint & Sample Client — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenAI-compatible mock model services and a standalone demo-client container that walks through the full TEE → KBS → plugin → Keycloak → model access flow including failure scenarios.

**Architecture:** A FastAPI mock model service validates Keycloak JWTs via JWKS and returns a hardcoded chat completion. A multi-stage `Dockerfile.client` embeds `kbs-client` (Rust binary) plus a Python script that drives all six scenarios end-to-end.

**Tech Stack:** FastAPI, uvicorn, PyJWT[crypto], jwcrypto, httpx, Docker Compose profiles, Rust (kbs-client binary from trustee repo)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `demo/mock-model/requirements.txt` | CREATE | Python deps for model service |
| `demo/mock-model/app.py` | CREATE | FastAPI app: JWKS validation + chat completions endpoint |
| `demo/mock-model/Dockerfile` | CREATE | python:3.12-slim image for model service |
| `demo/config/plugin-config.yaml` | MODIFY | Change endpoint scheme https→http |
| `demo/docker-compose.yml` | MODIFY | Add llama-8b, llama-70b, demo-client services |
| `demo/Dockerfile.client` | CREATE | Multi-stage: Rust builder (kbs-client) + Python runtime |
| `demo/demo-client.py` | CREATE | Six-scenario demo client |
| `demo/Makefile` | MODIFY | Add demo-client target |

---

## Task 1: Mock model service

**Files:**
- Create: `demo/mock-model/requirements.txt`
- Create: `demo/mock-model/app.py`
- Create: `demo/mock-model/Dockerfile`

- [ ] **Step 1: Create requirements.txt**

```
fastapi==0.115.12
uvicorn==0.34.2
PyJWT[crypto]==2.10.1
```

File: `demo/mock-model/requirements.txt`

- [ ] **Step 2: Create app.py**

```python
import os
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

MODEL_NAME = os.environ["MODEL_NAME"]
JWKS_URL = os.environ.get(
    "KEYCLOAK_JWKS_URL",
    "http://keycloak:8080/realms/ai-models/protocol/openid-connect/certs",
)

jwks_client = jwt.PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300)
app = FastAPI()


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return PlainTextResponse("missing or invalid token", status_code=401)
    token = auth[len("Bearer "):]
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            options={"verify_aud": False},
        )
    except Exception:
        return PlainTextResponse("invalid token", status_code=401)
    if MODEL_NAME not in claims.get("scope", "").split():
        return PlainTextResponse("insufficient scope", status_code=403)
    return JSONResponse({
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "model": MODEL_NAME,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": f"Hello from {MODEL_NAME}! (demo response)",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
    })
```

File: `demo/mock-model/app.py`

- [ ] **Step 3: Create Dockerfile**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
```

File: `demo/mock-model/Dockerfile`

- [ ] **Step 4: Build image and smoke-test missing-token path**

```bash
cd demo
docker build -t mock-model-test mock-model/
docker run -d -e MODEL_NAME=llama-8b -p 8099:8080 --name mock-model-test mock-model-test
sleep 2
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8099/v1/chat/completions)
echo "Expected 401, got: $STATUS"
docker rm -f mock-model-test
```

Expected output: `Expected 401, got: 401`

- [ ] **Step 5: Commit**

```bash
git add demo/mock-model/
git commit -s -m "Add mock OpenAI-compatible model service with JWKS token validation"
```

---

## Task 2: Plugin config update + model services in Compose

**Files:**
- Modify: `demo/config/plugin-config.yaml`
- Modify: `demo/docker-compose.yml`

- [ ] **Step 1: Update plugin-config.yaml endpoints to http**

Change both model endpoint URLs from `https://` to `http://`:

```yaml
models:
  llama-8b:
    endpoint: "http://llama-8b:8080"
    scope: llama-8b
  llama-70b:
    endpoint: "http://llama-70b:8080"
    scope: llama-70b
```

File: `demo/config/plugin-config.yaml` — only the two `endpoint:` lines change.

- [ ] **Step 2: Add llama-8b and llama-70b services to docker-compose.yml**

Add after the `opa:` service block and before `ai-gatekeeper:`:

```yaml
  llama-8b:
    build:
      context: ./mock-model
    environment:
      MODEL_NAME: llama-8b
    depends_on:
      keycloak:
        condition: service_healthy

  llama-70b:
    build:
      context: ./mock-model
    environment:
      MODEL_NAME: llama-70b
    depends_on:
      keycloak:
        condition: service_healthy
```

- [ ] **Step 3: Verify Compose config parses cleanly**

```bash
cd demo
docker compose config --quiet
echo "exit: $?"
```

Expected output: `exit: 0` (no errors)

- [ ] **Step 4: Commit**

```bash
git add demo/config/plugin-config.yaml demo/docker-compose.yml
git commit -s -m "Add mock model services to demo Compose stack; switch plugin endpoints to http"
```

---

## Task 3: Dockerfile.client

**Files:**
- Create: `demo/Dockerfile.client`

- [ ] **Step 1: Create Dockerfile.client**

Reuse the same Rust builder as `Dockerfile.kbs` but build only the `kbs-client` binary (skips the full KBS server compilation):

```dockerfile
# rust:1.90.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c \
    AS builder
ARG ARCH=x86_64

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    git \
    libclang-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    perl \
    pkg-config \
    protobuf-compiler \
    clang \
    cmake \
    libtss2-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/trustee
RUN git clone --depth=1 https://github.com/confidential-containers/trustee.git .
RUN cargo build -p kbs-client --release && \
    install target/release/kbs-client /usr/local/bin/kbs-client

FROM python:3.12-slim
RUN pip install --no-cache-dir \
    'PyJWT[crypto]' \
    cryptography \
    jwcrypto \
    httpx
COPY --from=builder /usr/local/bin/kbs-client /usr/local/bin/kbs-client
COPY demo-client.py /app/demo-client.py
WORKDIR /app
ENTRYPOINT ["python", "demo-client.py"]
```

File: `demo/Dockerfile.client`

- [ ] **Step 2: Commit**

```bash
git add demo/Dockerfile.client
git commit -s -m "Add Dockerfile.client: kbs-client binary + Python runtime for demo client"
```

---

## Task 4: demo-client.py + Compose service + Makefile target

**Files:**
- Create: `demo/demo-client.py`
- Modify: `demo/docker-compose.yml`
- Modify: `demo/Makefile`

- [ ] **Step 1: Create demo-client.py**

```python
#!/usr/bin/env python3
"""
Demo client — full TEE workload journey:
  attest → obtain scoped credentials → call model endpoint

Runs six scenarios (happy paths + failure cases) against a live demo stack.
"""
import json
import subprocess
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwcrypto import jwe as jwejwe
from jwcrypto import jwk

KBS_URL = "http://kbs:8080"
TEE_KEY_PATH = "/keys/tee.key"
PLUGIN_KEY_PATH = "/keys/plugin-token.key"

SEP = "━" * 50


def banner(title: str) -> None:
    print(f"\n{SEP}\n{title}\n{SEP}")


def attest() -> str:
    print("  Attesting to KBS...")
    result = subprocess.run(
        ["kbs-client", "--url", KBS_URL, "attest", "--tee-key-file", TEE_KEY_PATH],
        capture_output=True,
        text=True,
        check=True,
    )
    token = result.stdout.strip()
    print(f"  KBS token   : {token[:40]}...")
    return token


def make_plugin_jwt(role: str, key_path: str) -> str:
    with open(key_path, "rb") as f:
        key = load_pem_private_key(f.read(), None)
    return pyjwt.encode(
        {"role": role, "sub": "demo-tee", "exp": int(time.time()) + 300},
        key,
        algorithm="RS256",
    )


def call_plugin(model: str, plugin_jwt: str, kbs_token: str, tee_key) -> tuple[int, dict | None]:
    url = f"{KBS_URL}/kbs/v0/external/ai-gatekeeper/models/{model}"
    print(f"  Plugin call : POST /kbs/v0/external/ai-gatekeeper/models/{model}")
    with httpx.Client(timeout=15) as client:
        r = client.post(
            url,
            json={"token": plugin_jwt},
            headers={"Authorization": f"Bearer {kbs_token}"},
        )
    if r.status_code != 200:
        print(f"  Plugin      : {r.status_code}  {r.text.strip()}")
        return r.status_code, None
    tok = jwejwe.JWE()
    tok.deserialize(r.text.strip(), tee_key)
    payload = json.loads(tok.payload)
    print(f"  Plugin      : 200 OK  endpoint={payload['endpoint']}  token={payload['access_token'][:40]}...")
    return 200, payload


def call_model(endpoint: str, access_token: str) -> tuple[int, str]:
    url = f"{endpoint}/v1/chat/completions"
    print(f"  Model call  : POST {url}")
    with httpx.Client(timeout=10) as client:
        r = client.post(
            url,
            json={"model": "demo", "messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if r.status_code == 200:
        content = r.json()["choices"][0]["message"]["content"]
        print(f"  Model       : 200 OK  \"{content}\"")
    else:
        print(f"  Model       : {r.status_code}  {r.text.strip()}")
    return r.status_code, r.text


def result(ok: bool) -> None:
    print(f"  Result      : {'PASS' if ok else 'FAIL'}")


def main() -> None:
    print("Loading TEE key and generating plugin JWTs...")
    with open(TEE_KEY_PATH, "rb") as f:
        tee_key = jwk.JWK.from_pem(f.read())

    kbs_token = attest()

    jwt_basic = make_plugin_jwt("basic", PLUGIN_KEY_PATH)
    jwt_premium = make_plugin_jwt("premium", PLUGIN_KEY_PATH)

    # ── Scenario 1: premium role → llama-70b ──────────────────────────────
    banner("Scenario 1: Happy path — premium role → llama-70b")
    status, payload = call_plugin("llama-70b", jwt_premium, kbs_token, tee_key)
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        result(model_status == 200)
        token_70b = payload["access_token"]
    else:
        result(False)
        token_70b = None

    # ── Scenario 2: basic role → llama-8b ────────────────────────────────
    banner("Scenario 2: Happy path — basic role → llama-8b")
    status, payload = call_plugin("llama-8b", jwt_basic, kbs_token, tee_key)
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        result(model_status == 200)
        token_8b = payload["access_token"]
    else:
        result(False)
        token_8b = None

    # ── Scenario 3: basic role denied llama-70b ───────────────────────────
    banner("Scenario 3: Policy deny — basic role requests llama-70b")
    print("  (KBS returns 401; plugin internally returns 403 policy deny)")
    status, _ = call_plugin("llama-70b", jwt_basic, kbs_token, tee_key)
    result(status == 401)

    # ── Scenario 4: unknown model ─────────────────────────────────────────
    banner("Scenario 4: Unknown model — plugin returns 404 (KBS→401)")
    status, _ = call_plugin("llama-999", jwt_premium, kbs_token, tee_key)
    result(status == 401)

    # ── Scenario 5: tampered access token direct to model endpoint ────────
    banner("Scenario 5: Tampered access token — direct call to model endpoint")
    print("  (Bypasses KBS; model validates token independently via JWKS)")
    if token_70b:
        chars = list(token_70b)
        chars[10] = "X" if chars[10] != "X" else "Y"
        tampered = "".join(chars)
        model_status, _ = call_model("http://llama-70b:8080", tampered)
        result(model_status == 401)
    else:
        print("  Skipped (no token from scenario 1)")
        result(False)

    # ── Scenario 6: wrong scope direct to model endpoint ──────────────────
    banner("Scenario 6: Wrong scope — llama-8b token used against llama-70b endpoint")
    print("  (Bypasses KBS; model rejects token with mismatched scope)")
    if token_8b:
        model_status, _ = call_model("http://llama-70b:8080", token_8b)
        result(model_status == 403)
    else:
        print("  Skipped (no token from scenario 2)")
        result(False)

    print(f"\n{SEP}")
    print("Demo complete.")
    print(SEP)


if __name__ == "__main__":
    main()
```

File: `demo/demo-client.py`

- [ ] **Step 2: Add demo-client service to docker-compose.yml**

Add after the `test-runner:` service block:

```yaml
  demo-client:
    build:
      context: .
      dockerfile: Dockerfile.client
    volumes:
      - keys:/keys:ro
    depends_on:
      kbs:
        condition: service_started
      llama-8b:
        condition: service_started
      llama-70b:
        condition: service_started
    profiles:
      - demo
```

- [ ] **Step 3: Add demo-client target to Makefile**

Add to `demo/Makefile` (add `demo-client` to the `.PHONY` line and add the target):

```makefile
.PHONY: up down test demo demo-client logs

demo-client:
	$(COMPOSE) run --rm demo-client
```

- [ ] **Step 4: Build the demo-client image**

This builds the Rust kbs-client binary — takes ~5 min on a cold cache, seconds if Dockerfile.kbs builder layers are cached.

```bash
cd demo
docker compose build demo-client
echo "Build exit: $?"
```

Expected: `Build exit: 0`

- [ ] **Step 5: Run the full demo stack and execute the client**

```bash
cd demo
docker compose up -d --build
```

Wait ~60 s for Keycloak to be healthy, then:

```bash
docker compose --profile demo run --rm demo-client
```

Expected: all six scenarios print their banner and result line. Scenarios 1 and 2 show `200 OK` from the model with a chat response. Scenarios 3 and 4 show plugin `401`. Scenarios 5 and 6 show model `401` and `403` respectively. Final line: `Demo complete.`

If anything fails, check service logs:
```bash
docker compose logs llama-8b llama-70b ai-gatekeeper
```

- [ ] **Step 6: Tear down**

```bash
docker compose --profile demo down -v --remove-orphans
```

- [ ] **Step 7: Commit**

```bash
git add demo/demo-client.py demo/docker-compose.yml demo/Makefile
git commit -s -m "Add demo-client: six-scenario end-to-end walkthrough with mock model endpoints"
```

---

## Self-Review

**Spec coverage:**
- Mock model service (JWKS validation, scope check, OpenAI response, error codes) → Task 1 ✓
- Plugin config https→http → Task 2 ✓
- llama-8b / llama-70b Compose services → Task 2 ✓
- Dockerfile.client multi-stage → Task 3 ✓
- demo-client.py: attest, sign JWTs, call plugin, decrypt JWE, call model → Task 4 ✓
- All six scenarios → Task 4 ✓
- demo-client Compose service under `demo` profile → Task 4 ✓
- Makefile `demo-client` target → Task 4 ✓

**Placeholder scan:** None found.

**Type consistency:**
- `call_plugin` returns `(int, dict | None)` — used as `status, payload` in all scenarios ✓
- `call_model` returns `(int, str)` — used as `model_status, _` in scenarios 1–2 and `model_status, _` in 5–6 ✓
- `tee_key` is a `jwk.JWK` object — passed to `jwejwe.JWE().deserialize(raw, tee_key)` which accepts JWK ✓
- `token_70b` and `token_8b` set in scenarios 1/2 and consumed in 5/6 — guarded with `if token_70b` / `if token_8b` ✓
