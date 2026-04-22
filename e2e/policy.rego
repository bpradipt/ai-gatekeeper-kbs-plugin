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
