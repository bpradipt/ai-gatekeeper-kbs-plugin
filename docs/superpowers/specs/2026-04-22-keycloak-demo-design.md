# Demo: Real Keycloak + KBS + AI Gatekeeper

**Date:** 2026-04-22
**Status:** Approved

## Goal

Add a `demo/` directory with a fully self-contained Docker Compose stack that replaces the mock Keycloak in `e2e/` with a real Keycloak instance. The existing `e2e/` stack is not modified. The demo proves the full server-side integration — real OIDC client-credentials flow — while using the same test client approach as the existing e2e tests.

## Directory Structure

```
demo/
├── docker-compose.yml
├── Makefile
├── Dockerfile.kbs              # Copy of e2e/Dockerfile.kbs
├── Dockerfile.test-runner      # Copy of e2e/Dockerfile.test-runner
├── policy.rego                 # Copy of e2e/policy.rego
├── config/
│   ├── kbs.toml
│   ├── plugin-config.yaml
│   └── realm.json              # Keycloak realm import
├── secrets/
│   └── kc-secret               # Contains "demo-secret-change-me"
└── tests/
    └── demo.sh
```

The `demo/` directory is fully self-contained. No files are shared with `e2e/`. This allows the demo to evolve independently.

## Services

| Service | Image / Build | Purpose |
|---|---|---|
| `setup` | `alpine/openssl` | One-shot: generates RSA/EC keys into a shared volume |
| `keycloak` | `quay.io/keycloak/keycloak:26.6.1` | Real Keycloak; imports realm at startup |
| `opa` | `openpolicyagent/opa:1.15.2-static` | Policy evaluation |
| `ai-gatekeeper` | Built from repo root `Dockerfile` | gRPC plugin |
| `kbs` | Built from `demo/Dockerfile.kbs` | Trustee KBS with external plugin support |
| `test-runner` | Built from `demo/Dockerfile.test-runner` | Python image for one-shot JWT generation |

## Startup Sequence

```
setup (completes)
  ├──> keycloak  (starts, health-checked at /health/ready)
  │         └──> ai-gatekeeper  (waits: setup done + keycloak healthy)
  │                   └──> kbs  (waits: setup done + ai-gatekeeper started)
  └──> opa  (waits: setup done)
```

`ai-gatekeeper` uses `depends_on: keycloak: condition: service_healthy` because Keycloak takes 20–30 s to boot. Without this gate the plugin fails on first startup trying to reach Keycloak before it is ready.

## Keycloak Configuration (`config/realm.json`)

- **Realm:** `ai-models`
- **SSL:** required for external requests only (dev-friendly; Keycloak runs on plain HTTP inside the compose network)
- **Client:** `ai-gatekeeper`
  - `serviceAccountsEnabled: true` — enables client-credentials grant
  - `clientAuthenticatorType: client-secret`
  - `secret: demo-secret-change-me`
  - Standard browser/password flows disabled — service account only
- **Client scopes:** `llama-8b` and `llama-70b` defined at realm level, assigned as optional scopes on the client. Keycloak includes the requested scope in the issued token rather than silently dropping it.
- **Default scopes stripped:** `profile`, `email`, `roles`, `web-origins` removed from the client's default scope list to keep tokens minimal.

Keycloak is started with:
```
start-dev --import-realm --health-enabled=true
```

The realm JSON is mounted at `/opt/keycloak/data/import/`.

Keycloak admin console is exposed on host port `8180` (KBS uses `8080`) so both can run simultaneously without port conflict.

## Plugin Configuration (`config/plugin-config.yaml`)

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

The secret file `demo/secrets/kc-secret` contains the literal string `demo-secret-change-me` and is mounted read-only into the container at `/run/secrets/kc-secret`.

## Test Script (`tests/demo.sh`)

Same five test cases as `e2e/tests/e2e.sh`:

1. `basic` role + `llama-8b` → 200
2. `basic` role + `llama-70b` → 401 (policy deny, KBS normalises to 401)
3. `premium` role + `llama-70b` → 200
4. unknown model → 401
5. missing token → 401

JWT generation uses a one-shot `docker compose run test-runner` (PyJWT), same as the e2e script. The KBS attestation token is obtained via `docker compose exec kbs kbs-client`.

## Makefile Targets

| Target | Action |
|---|---|
| `up` | `docker compose up -d --build` |
| `test` | Run `tests/demo.sh` |
| `demo` | `up` + `test` |
| `down` | `docker compose down -v` |
| `logs` | `docker compose logs -f` |

## README

The `demo/README.md` covers:
1. Prerequisites (Docker, Docker Compose v2)
2. `make demo` one-liner
3. Service table and what each does
4. Keycloak admin console access (`http://localhost:8180`, credentials `admin`/`admin`)
5. Tear-down instructions
6. Note on demo secret — label it clearly as not production-safe

## What Is Not Changing

- `e2e/` — untouched
- `ai_gatekeeper/` source — untouched
- `Dockerfile` at repo root — reused as-is by demo build context
