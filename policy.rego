package ai_gatekeeper

import rego.v1

default allow := false

# Role-based access: map role claim to allowed models.
allow if {
    allowed_models[input.claims.role][input.model]
}

# Measurement-based override: a specific TDX enclave gets research access.
# Replace mr_td value with your enclave's measurement.
allow if {
    input.claims.tee == "tdx"
    input.claims["td-attributes"].mr_td == "replace-with-your-mrtd"
    allowed_models.research[input.model]
}

allowed_models := {
    "basic":    {"llama-8b":  true},
    "premium":  {"llama-8b":  true, "llama-70b": true},
    "research": {"llama-8b":  true, "llama-70b": true},
}
