package ai_gatekeeper

import rego.v1

default allow := false

# Role is read from the initdata TOML passed at attestation time.
# The initdata is cryptographically bound to TEE evidence:
#   TDX  → mr_config_id   SNP → hostdata   vTPM → PCR[8]
# On sample TEE (testing only) the hash is not hardware-verified.
#
# Initdata format (passed as plaintext to kbs-client attest):
#   algorithm = "sha256"
#   version = "0.1.0"
#
#   [data]
#   role = "basic"   # or "premium", "research", ...
#   "aa.toml" = '''
#   [token_configs.kbs]
#   url = "http://<kbs-host>:<port>"
#   '''
#
# See DEPLOYMENT.md for hash computation and per-TEE-type guidance.
role := r if {
    r := input.claims.init_data_claims["role"]
}

allow if {
    allowed_models[role][input.model]
}

# Measurement-based override: a specific TDX enclave gets research access
# regardless of initdata. Replace with your enclave's mr_td value.
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
