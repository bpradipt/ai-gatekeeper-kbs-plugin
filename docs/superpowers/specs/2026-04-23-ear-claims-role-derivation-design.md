# Design: EAR Claims Normalization and Init-Data Role Derivation

**Date:** 2026-04-23
**Status:** Approved

## Problem

The current plugin uses a separate `plugin-token.key` to sign a body JWT carrying a self-asserted `role` claim. This key is generated at deploy time and distributed independently of TEE attestation — anyone holding it can forge any role. The demo client calls `make_plugin_jwt("premium")` directly, which has no cryptographic connection to the KBS RCAR handshake.

Additionally, the real KBS attestation JWT uses EAR (Entity Attestation Result) format with a nested structure (`submods.cpu0["ear.veraison.annotated-evidence"].*`) that the Rego policy cannot read with its current flat-claim assumptions.

## Goal

- Body JWT = the real KBS attestation JWT (same token the client received from `/kbs/v0/attest`)
- Plugin verifies it against the KBS token signing cert (`token-cert-chain.pem`)
- Plugin normalizes the EAR structure into a flat, documented claim set before Rego sees it
- Role is derived entirely inside Rego from the normalized `init_data_hash` claim
- Demo accurately represents a production deployment: no separate signing keys, no self-asserted roles

## Design

### 1. EAR Claim Normalizer (`ai_gatekeeper/ear_normalizer.py`)

New module with a single function `normalize(ear_claims: dict) -> dict`. Called by the handler after JWT verification, before Rego evaluation.

**Normalized output (the documented operator interface):**

```python
{
    "tee_type":       str,         # TEE platform: "sample" | "tdx" | "snp" | "sgx" | ...
    "ear_status":     str,         # EAR verdict: "affirming" | "warning" | "contraindicated"
    "init_data_hash": str | None,  # base64url SHA-256 of init-data blob; None if not provided
    "measurement":    str | None,  # primary measurement register:
                                   #   sample → launch_digest
                                   #   TDX    → mr_td (from td-attributes)
                                   #   SNP    → measurement
                                   #   None if TEE type is unknown
    "debug":          bool | None, # debug mode flag; None if not present
}
```

**EAR source paths:**

| Output field      | EAR path                                                                          |
|-------------------|-----------------------------------------------------------------------------------|
| `tee_type`        | key of TEE-specific sub-object inside `submods.cpu0["ear.veraison.annotated-evidence"]` |
| `ear_status`      | `submods.cpu0["ear.status"]`                                                      |
| `init_data_hash`  | `submods.cpu0["ear.veraison.annotated-evidence"].init_data`                       |
| `measurement`     | `annotated-evidence.<tee_type>.launch_digest` (sample) / `.mr_td` (TDX, verify against real EAR output) / `.measurement` (SNP) |
| `debug`           | `annotated-evidence.<tee_type>.debug`                                             |

Known non-TEE keys excluded from TEE type detection: `report_data`, `init_data`, `init_data_claims`, `runtime_data_claims`.

If the EAR structure is malformed or a field is absent, the normalizer returns `None` for that field rather than raising — a missing `init_data_hash` simply won't match any Rego `role_map` entry, causing deny.

### 2. Handler Change

After JWT verification, handler calls normalizer and passes the result to Rego:

```python
claims = self._verifier.verify(token)          # returns raw EAR JWT payload
normalized = normalize_ear_claims(claims)      # flatten to operator-facing structure
if not await self._rego.allow(normalized, model_name):
    ...
```

No other handler logic changes.

### 3. Rego Policy

The policy owns role derivation. `role_map` maps known `init_data_hash` values to role names. Operators extend this table for new TEE configurations.

```rego
package ai_gatekeeper

import rego.v1

default allow := false

# Role map: base64url(sha256(init-data-string)) → role name.
# Compute a hash: printf '<string>' | sha256sum | awk '{print $1}' \
#                 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '='
# On real hardware (TDX/SNP), init-data is cryptographically measured and bound
# to the TEE evidence — these hashes cannot be forged by the workload.
# See DEPLOYMENT.md for per-TEE-type configuration guidance.
role_map := {
    "IWjlrrHiZjz0SmFAWXDdSbqZcnLytZIOVGNgYJzv4b8": "basic",    # sha256('{"role":"basic"}')
    "IpkBARc5Qjrihj0OgyegL4oTF-uuWVyAvtv8swX6Kv4": "premium",  # sha256('{"role":"premium"}')
}

role := r if { r := role_map[input.claims.init_data_hash] }

allow if {
    allowed_models[role][input.model]
}

# Measurement-based override: a specific TDX enclave gets research access regardless of init-data.
# Replace with your enclave's mr_td value from `kbs-client get-resource` attestation output.
allow if {
    input.claims.tee_type == "tdx"
    input.claims.measurement == "replace-with-your-mr-td"
    allowed_models.research[input.model]
}

allowed_models := {
    "basic":    {"llama-8b":  true},
    "premium":  {"llama-8b":  true, "llama-70b": true},
    "research": {"llama-8b":  true, "llama-70b": true},
}
```

### 4. Config Changes

**`token_cert_path`** changes from `plugin-token-cert.pem` → `token-cert-chain.pem` (the KBS token signing cert) in all environments: `config.yaml`, `e2e/config/plugin-config.yaml`, `demo/config/plugin-config.yaml`.

`audience` stays `""` for demo/e2e with an inline comment: `# set to your KBS issuer URL in production`.

### 5. Key Hygiene

`plugin-token.key` and `plugin-token-cert.pem` are removed from the `setup` service in both `e2e/docker-compose.yml` and `demo/docker-compose.yml`. They are no longer generated or mounted.

### 6. Demo Client (`demo/demo-client.py`)

Remove `make_plugin_jwt()` and `PLUGIN_KEY_PATH`. Attest twice with different init-data:

```python
kbs_token_basic   = attest(init_data='{"role":"basic"}')
kbs_token_premium = attest(init_data='{"role":"premium"}')
```

`attest()` gains an optional `init_data` parameter, added as a positional argument to the `kbs-client attest` subprocess call.

Body token is the KBS attestation JWT directly — no separate signing key:

```python
call_plugin("llama-8b",  body_token=kbs_token_basic,   kbs_token=kbs_token_basic)
call_plugin("llama-70b", body_token=kbs_token_premium,  kbs_token=kbs_token_premium)
```

All 6 demo scenarios are preserved. The two demo `policy.rego` hashes (`IWjl...` and `IpkB...`) are pre-computed from `'{"role":"basic"}'` and `'{"role":"premium"}'`.

### 7. E2E Tests (`e2e/tests/e2e.sh`)

Two `kbs-client attest <init-data>` calls replace the `test-runner` JWT generation step. Body token = KBS JWT directly. All existing test cases (basic+llama-8b, basic denied llama-70b, premium+llama-70b, unknown model, missing token) are preserved.

### 8. Documentation

- **`DEPLOYMENT.md`** (new): normalized claims reference, init-data hash computation recipe, per-TEE-type guidance (sample/TDX/SNP), production hardening checklist (audience, TLS, file permissions, Rego `role_map` management)
- **`README.md`**: update request flow diagram and Authentication Layers section to reflect real KBS JWT in body; remove mention of separate plugin JWT key
- **`ear_normalizer.py`**: module docstring describes the EAR → normalized mapping; inline comments on each TEE-type extraction path

## Files Changed

| File | Change |
|------|--------|
| `ai_gatekeeper/ear_normalizer.py` | New |
| `ai_gatekeeper/handler.py` | Call normalizer before Rego |
| `policy.rego` | Role derivation from `init_data_hash`; update claim paths |
| `demo/policy.rego` | Same; pre-computed demo hashes |
| `e2e/policy.rego` | Same |
| `config.yaml` | `token_cert_path` → KBS cert |
| `demo/config/plugin-config.yaml` | Same |
| `e2e/config/plugin-config.yaml` | Same; `token_cert_path` → `token-cert-chain.pem` |
| `demo/demo-client.py` | Remove `make_plugin_jwt`; attest with init-data |
| `demo/docker-compose.yml` | Remove `plugin-token.key` generation |
| `e2e/docker-compose.yml` | Remove `plugin-token.key` generation; remove `test-runner` service (was only used for JWT generation) |
| `e2e/tests/e2e.sh` | Attest with init-data; body = KBS JWT |
| `tests/test_handler.py` | Update fixtures to use normalized EAR claims |
| `tests/test_policy.py` | Update to use `init_data_hash` based claims |
| `README.md` | Update flow description |
| `DEPLOYMENT.md` | New |

## What Does Not Change

- `JwtVerifier` — unchanged; still verifies RS256/ES256 via cert
- `KeycloakClient` — unchanged
- `RegoEvaluator` — unchanged
- `Config` — unchanged (no new config sections needed)
- gRPC server setup — unchanged
- `validate_auth()` returning `False` — unchanged
- `needs_encryption()` returning `True` — unchanged
