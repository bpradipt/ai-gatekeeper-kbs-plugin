# AI Gatekeeper — Demo with Real Keycloak

Brings up a complete local stack: Trustee KBS, the ai-gatekeeper gRPC plugin, OPA, real Keycloak 26.6.1, and two mock OpenAI-compatible model endpoints — then lets you run either the automated assertion tests or a full narrative demo client.

## Prerequisites

- Docker and Docker Compose v2 (`docker compose version`)
- `curl`, `python3` on the host (used by the test script)

## Quick Start

**Automated assertion tests** (pass/fail, used for CI):

```bash
cd demo
make demo
```

`make demo` builds all images, starts all services, runs the assertion tests, then tears down the stack.

**Narrative demo client** (six scenarios with visible inputs and outputs, for stakeholders):

```bash
cd demo
make up          # start the stack in the background
make demo-client # run the demo client; re-run as many times as you like
make down        # tear down when done
```

First run builds KBS from source (~10–20 min depending on CPU/network). Subsequent runs reuse the image cache.

## How It Works

```
TEE client (kbs-client)
  1. RCAR handshake → presents ephemeral EC public key, receives KBS attestation token
  2. POST /kbs/v0/external/ai-gatekeeper/models/<model>
       Authorization: Bearer <kbs-token>
       body: {"token": "<plugin-JWT>"}
  3. KBS validates attestation, calls ai-gatekeeper plugin
  4. Plugin: verifies plugin-JWT → OPA policy check → Keycloak client-credentials token
  5. Plugin returns {"endpoint": "...", "access_token": "<keycloak-token>"}
  6. KBS JWE-encrypts the response with the TEE's ephemeral public key
  7. TEE client decrypts with its ephemeral private key (tee.key)
```

The test script simulates the TEE client: it calls `kbs-client attest` to complete the RCAR
handshake (establishing the ephemeral key pair), then uses `curl` for the plugin request and
decrypts the JWE response using `tee.key` — showing the plaintext `endpoint` and
`access_token` that only the attested TEE can read.

## Services

| Service | Host Port | Purpose |
|---|---|---|
| `keycloak` | 8180 | Keycloak 26.6.1 — issues OIDC tokens for model scopes |
| `kbs` | 8080 | Trustee Key Broker Service — attestation and plugin proxy |
| `ai-gatekeeper` | 50051 | gRPC plugin — JWT verify, policy eval, Keycloak token exchange |
| `opa` | — | OPA server — evaluates the Rego access policy |
| `llama-8b` | — | Mock OpenAI-compatible endpoint; validates Keycloak JWTs via JWKS |
| `llama-70b` | — | Mock OpenAI-compatible endpoint; validates Keycloak JWTs via JWKS |
| `setup` | — | One-shot key generation (RSA, EC, TLS certs) |
| `test-runner` | — | Python image for JWT generation and JWE decryption (used by `make test`) |
| `demo-client` | — | Six-scenario narrative client (started via `make demo-client` only) |

## Keycloak Admin Console

After `make up`, open: http://localhost:8180

Credentials: `admin` / `admin`

The `ai-models` realm and `ai-gatekeeper` client are imported automatically on first start.

## Individual Targets

```bash
make up           # Start all services in background (build first)
make test         # Run assertion tests against a running stack
make demo-client  # Run the six-scenario narrative demo against a running stack
make logs         # Follow service logs
make down         # Stop and remove containers and volumes
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
