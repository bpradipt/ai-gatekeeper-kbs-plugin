---
title: Demo — Mock Model Endpoint & Sample Client
date: 2026-04-23
status: approved
---

# Demo — Mock Model Endpoint & Sample Client

## Goal

Extend the demo stack with realistic mock AI model endpoints and a standalone
sample client that completes the full TEE workload journey: attest → obtain
scoped credentials → call model. The extended demo is aimed at stakeholders and
developers who need to see the entire access-control story end-to-end, including
failure scenarios.

## Current State

The demo stack (`demo/`) runs KBS + ai-gatekeeper plugin + real Keycloak. The
plugin config references `https://llama-8b:8080` and `https://llama-70b:8080`
as model endpoints, but no services exist at those addresses. `demo.sh` verifies
HTTP status codes and decrypts the JWE response to show `endpoint` +
`access_token`, but the access token is never used.

## What Is Added

### 1. Mock Model Service (`demo/mock-model/`)

A single-file FastAPI application that simulates an OpenAI-compatible inference
endpoint with real token validation.

**API:** `POST /v1/chat/completions`

**Token validation (JWKS):**
- On startup: fetch `http://keycloak:8080/realms/ai-models/protocol/openid-connect/certs` and initialise a `PyJWKClient` (cached for the process lifetime).
- Per request: validate JWT signature and expiry; return `401` if invalid or missing.
- Check that the `scope` claim contains `MODEL_NAME` (injected via env var); return `403` if the scope does not match.

**Success response (hardcoded, OpenAI-compatible):**
```json
{
  "id": "chatcmpl-demo",
  "object": "chat.completion",
  "model": "<MODEL_NAME>",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "Hello from <MODEL_NAME>! (demo response)"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18}
}
```

**Error responses:**

| Condition | Status | Body |
|---|---|---|
| Missing / malformed `Authorization` header | 401 | `missing or invalid token` |
| JWT signature / expiry invalid | 401 | `invalid token` |
| `scope` does not include model name | 403 | `insufficient scope` |

**Files:**
- `demo/mock-model/app.py` — FastAPI app (~60 lines)
- `demo/mock-model/requirements.txt` — `fastapi`, `uvicorn`, `PyJWT[crypto]`
- `demo/mock-model/Dockerfile` — `python:3.12-slim`, pip install, `uvicorn app:app`

**Docker Compose services:**

Two service entries using the same image, differentiated by `MODEL_NAME`:

```yaml
llama-8b:
  build: { context: ./mock-model }
  environment: { MODEL_NAME: llama-8b }
  depends_on:
    keycloak: { condition: service_healthy }

llama-70b:
  build: { context: ./mock-model }
  environment: { MODEL_NAME: llama-70b }
  depends_on:
    keycloak: { condition: service_healthy }
```

### 2. Plugin Config Update

Change model endpoints from `https://` to `http://` — no TLS needed for
intra-Compose traffic:

```yaml
models:
  llama-8b:
    endpoint: "http://llama-8b:8080"
    scope: llama-8b
  llama-70b:
    endpoint: "http://llama-70b:8080"
    scope: llama-70b
```

### 3. `demo-client` Service

A one-shot container that runs `demo-client.py` and exits. Added under a
`demo` Compose profile so it is not started by `make up`.

**`demo/Dockerfile.client` — multi-stage:**

```
Stage 1 (builder): same Rust image as Dockerfile.kbs
  - builds kbs-client binary only (cargo build -p kbs-client --release)

Stage 2 (runtime): python:3.12-slim
  - copies /usr/local/bin/kbs-client from builder
  - pip install PyJWT[crypto] jwcrypto httpx cryptography
  - copies demo-client.py
```

**`demo/demo-client.py` — sequential scenarios:**

Shared setup (runs once):
1. `kbs-client attest --url http://kbs:8080 --tee-key-file /keys/tee.key` → `KBS_TOKEN`
2. Sign two plugin JWTs (`role=basic`, `role=premium`) using `/keys/plugin-token.key`
3. Load TEE private key (`/keys/tee.key`) for JWE decryption

Helper `call_plugin(model, jwt)`:
- `POST /kbs/v0/external/ai-gatekeeper/models/<model>` with KBS_TOKEN + plugin JWT
- If 200: decrypt JWE with TEE key → `{endpoint, access_token}`
- Else: return `(status, None, None)`

Helper `call_model(endpoint, access_token)`:
- `POST <endpoint>/v1/chat/completions` with `Authorization: Bearer <access_token>`
- Minimal chat payload: `{"model": "...", "messages": [{"role": "user", "content": "Hello"}]}`

**Scenarios (printed with banners, exit 0 always):**

| # | Name | JWT role | Model | Expected |
|---|---|---|---|---|
| 1 | Happy path — premium + llama-70b | premium | llama-70b | Plugin 200 → model 200 + chat response |
| 2 | Happy path — basic + llama-8b | basic | llama-8b | Plugin 200 → model 200 + chat response |
| 3 | Policy deny — basic role requests llama-70b | basic | llama-70b | KBS 401 (plugin: 403) |
| 4 | Unknown model | premium | llama-999 | KBS 401 (plugin: 404) |
| 5 | Tampered access token → model endpoint | (uses token from scenario 1, mutates char 10) | llama-70b (direct) | Model 401 |
| 6 | Wrong scope → model endpoint | (uses llama-8b token from scenario 2, calls llama-70b directly) | llama-70b (direct) | Model 403 |

Scenarios 5 and 6 bypass KBS and hit the model endpoint directly, demonstrating
that the model enforces its own token validation independently.

**Output format per scenario:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scenario 1: Happy path — premium role → llama-70b
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Plugin call : POST /kbs/v0/external/ai-gatekeeper/models/llama-70b
  Plugin      : 200 OK  endpoint=http://llama-70b:8080  token=eyJ...(truncated)
  Model call  : POST http://llama-70b:8080/v1/chat/completions
  Model       : 200 OK  "Hello from llama-70b! (demo response)"
  Result      : PASS
```

### 4. Makefile Update (`demo/Makefile`)

```makefile
demo-client:
	$(COMPOSE) run --rm demo-client
```

Running `make demo-client` against an already-running stack executes the client.
`make demo` continues to run `demo.sh` (the assertion-based test suite) unchanged.

## Files Changed / Added

```
demo/
  mock-model/
    app.py                   NEW
    requirements.txt         NEW
    Dockerfile               NEW
  Dockerfile.client          NEW
  demo-client.py             NEW
  docker-compose.yml         MODIFIED  (llama-8b, llama-70b, demo-client services; https→http in plugin config)
  config/plugin-config.yaml  MODIFIED  (https→http endpoints)
  Makefile                   MODIFIED  (demo-client target)
```

## Out of Scope

- TLS between demo services (intra-Compose HTTP is sufficient)
- Streaming responses from the mock model
- Multiple users / concurrent requests
- Any changes to `e2e/`
