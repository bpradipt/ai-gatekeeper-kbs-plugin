# Deployment Guide

This guide covers production deployment of the AI Gatekeeper KBS plugin. For a
local demo, see [`demo/README.md`](demo/README.md).

## How Role Derivation Works

The plugin receives the KBS attestation JWT (EAR format) in the request body.
After verifying the JWT signature, it normalizes the EAR claims and passes them
to the Rego policy.

The role is read from the initdata TOML the TEE provided at attestation time.
KBS verifies the initdata hash against the TEE hardware evidence and exposes the
parsed initdata content as `init_data_claims` in the EAR JWT:

```
Initdata TOML (plaintext)
        │
        ▼ hash (sha256/sha384 per algorithm field)
TEE hardware evidence
  TDX → mr_config_id
  SNP → hostdata
  vTPM → PCR[8]
        │
        ▼ KBS verifies hash and parses plaintext
init_data_claims in EAR JWT
  ["aa.toml"]["extra"]["role"] = "basic" | "premium" | "research"
        │
        ▼ Rego policy
allow / deny
```

On real hardware (TDX, SNP, vTPM), the initdata hash is cryptographically bound
to the TEE evidence. The workload cannot substitute a different initdata value
after launch.

## Initdata Format

The initdata passed to `kbs-client attest` must follow the CoCo initdata spec
(version `0.1.0`). The role is placed in the `[extra]` section of `aa.toml`:

```toml
version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = """
[token_configs.kbs]
url = "http://<kbs-host>:<port>"

[extra]
role = "basic"   # or "premium", "research", ...
"""
```

The `algorithm` field (`sha256`, `sha384`, or `sha512`) determines which hash
algorithm is used to compute the initdata digest for the hardware register.

## Normalized Claims Reference

The plugin exposes these fields to Rego as `input.claims`:

| Field | Type | Description |
|-------|------|-------------|
| `tee_type` | `string \| null` | TEE platform: `"tdx"`, `"snp"`, `"sgx"`, `"sample"`, ... |
| `ear_status` | `string \| null` | EAR verdict: `"affirming"`, `"warning"`, `"contraindicated"` |
| `init_data_hash` | `string \| null` | Hash of the initdata blob from the hardware register; `null` if no initdata was provided |
| `init_data_claims` | `dict \| null` | Parsed content of the initdata TOML; `null` if no initdata plaintext was provided. Contains sub-keys matching the `[data]` section (e.g. `"aa.toml"`, `"cdh.toml"`) |
| `measurement` | `string \| null` | Primary measurement register (see table below) |
| `debug` | `bool \| null` | Debug mode flag from TEE evidence |

**Measurement field by TEE type:**

| TEE type | Source field | Notes |
|----------|-------------|-------|
| `sample` | `launch_digest` | Fixed value `"abcde"` — for testing only |
| `tdx` | `mr_td` | TDX measurement register; verify path against real EAR output |
| `snp` | `measurement` | SNP measurement |
| `sgx` | `mrenclave` | SGX enclave measurement |

## Writing Rego Policies

The Rego policy reads the role from `init_data_claims`:

```rego
role := r if {
    r := input.claims.init_data_claims["aa.toml"]["extra"]["role"]
}

allow if {
    allowed_models[role][input.model]
}
```

You can place any fields you need in the `[extra]` section of `aa.toml` in the
initdata TOML. You can also add other files to the `[data]` section — their
parsed content will appear under the corresponding key in `init_data_claims`.

## Per-TEE-Type Configuration

### Intel TDX

Pass the initdata TOML at VM launch via the `mr_config_id` mechanism (e.g.,
through QEMU or Kata Containers `RuntimeClass` configuration). The initdata hash
is automatically written into `mr_config_id` at launch and signed by the CPU.

Replace the measurement-based override placeholder in `policy.rego` if needed:

```rego
allow if {
    input.claims.tee_type == "tdx"
    input.claims.measurement == "<your-enclave-mr-td>"
    allowed_models.research[input.model]
}
```

### AMD SNP

Pass initdata via the SNP guest configuration. The hash is written into
`hostdata` (32 bytes). The same Rego policy pattern applies.

### vTPM (SW TPM / Azure vTPM)

The Attestation Agent extends the initdata hash into PCR[8] after launch. The
same initdata TOML format and Rego policy apply.

### Sample TEE (testing only)

The `sample` TEE type includes the initdata hash and `init_data_claims` in the
EAR JWT, but does not cryptographically verify the hash against hardware
evidence. It is suitable for local development and CI only — never use sample
TEE in production.

## Production Hardening Checklist

- [ ] **Audience validation**: Set `audience` in `config.yaml` to your KBS issuer
  URL. Leaving it empty disables audience checks and logs a warning.
- [ ] **TLS on gRPC**: Enable `server.tls` in `config.yaml` with a valid cert/key
  pair for the KBS → plugin gRPC connection.
- [ ] **File permissions**: `token-cert-chain.pem` and `kc-secret` should be
  readable only by the plugin process (`chmod 400`).
- [ ] **OPA policy mount**: Mount `policy.rego` read-only (`ro`) in the OPA
  container to prevent runtime policy modification.
- [ ] **Keycloak secret rotation**: Rotate `kc-secret` regularly. The plugin
  loads it at startup — restart after rotation.
- [ ] **`ear_status` filtering** (optional): Add a policy rule to deny requests
  with `ear_status != "affirming"` for strict compliance environments.
