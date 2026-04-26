# Initdata Format Fix — Design Spec

**Date:** 2026-04-26
**Status:** Approved

## Problem

The initdata TOML passed to `kbs-client attest` uses two incorrect conventions:

1. **Wrong quote style**: multi-line strings use `"""` (TOML basic string) instead of `'''` (TOML literal string)
2. **Wrong role placement**: `role = "basic"` is nested inside `[extra]` within `aa.toml` instead of being a top-level key-value pair in the initdata TOML

The correct format per the CoCo initdata spec places arbitrary metadata (like `role`) as top-level key=value pairs alongside `algorithm` and `version`. The `[data]` section is for config file distribution only.

## Correct Initdata Format

```toml
algorithm = "sha256"
version = "0.1.0"
role = "basic"           # top-level, no subsection

[data]
"aa.toml" = '''
[token_configs.kbs]
url = "http://localhost:8080"
'''
"cdh.toml" = '''
socket = 'unix:///run/confidential-containers/cdh.sock'
credentials = []

[kbc]
name = "cc_kbc"
url = "http://localhost:8080"
'''
"policy.rego" = '''
'''
```

Key rules:
- Triple single quotes `'''` for all multi-line file values (TOML literal multi-line strings)
- `role = "<value>"` at the top level of the TOML, not inside any section
- `aa.toml` content contains only `[token_configs.kbs]` (no `[extra]` subsection)
- `cdh.toml` and `policy.rego` entries are included in `[data]`

## Impact on `init_data_claims` Access Path

KBS exposes top-level initdata keys directly in the `init_data_claims` dict in the EAR JWT.

| Before (incorrect) | After (correct) |
|---|---|
| `init_data_claims["aa.toml"]["extra"]["role"]` | `init_data_claims["role"]` |

## Files to Change

### Shell scripts
- `e2e/tests/e2e.sh` — two initdata blocks (basic, premium)
- `demo/tests/demo.sh` — two initdata blocks (basic, premium)

### Python demo client
- `demo/demo-client.py` — `_initdata()` function body + docstring/comment references

### Rego policies (3 files)
- `policy.rego`
- `e2e/policy.rego`
- `demo/policy.rego`

All three: update access path and update inline comments showing the format.

### Python tests
- `tests/test_policy.py` — `_claims()` helper and `test_missing_role_in_extra_denied` test name/body
- `tests/test_handler.py` — fixture `init_data_claims` structure
- `tests/test_ear_normalizer.py` — `test_init_data_claims_present` fixture

### Documentation
- `ai_gatekeeper/ear_normalizer.py` — docstring example access path
- `README.md` — access path reference
- `DEPLOYMENT.md` — full initdata format example + claims table + Rego snippet + custom fields section

## Non-Goals

- No changes to the EAR normalizer logic (it passes `init_data_claims` through as-is)
- No changes to the handler, JWT verifier, or Keycloak integration
- No changes to the OPA evaluator or the allowed_models table in Rego
