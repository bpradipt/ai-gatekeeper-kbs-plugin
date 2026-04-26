"""
Tests for policy.rego using a real OPA subprocess.

These tests run `opa eval` against the actual policy file so that any change
to policy.rego is immediately caught.  They are skipped automatically if the
`opa` binary is not on PATH (e.g. in environments where only the OPA HTTP
sidecar is used).
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

POLICY = Path(__file__).parent.parent / "policy.rego"

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None, reason="opa binary not found"
)

# Helper: build the init_data_claims dict for a given role.
# Role is a top-level key in the initdata TOML, not nested under [data].
def _claims(role: str) -> dict:
    return {"init_data_claims": {"role": role}}


def _allow(claims: dict, model: str) -> bool:
    result = subprocess.run(
        [
            "opa", "eval",
            "--data", str(POLICY),
            "--input", "/dev/stdin",
            "--format", "raw",
            "data.ai_gatekeeper.allow",
        ],
        input=json.dumps({"claims": claims, "model": model}).encode(),
        capture_output=True,
        timeout=5,
    )
    return result.stdout.strip() == b"true"


# ── role-based access via init_data_claims ────────────────────────────────────

def test_basic_allows_llama8b():
    assert _allow(_claims("basic"), "llama-8b") is True


def test_basic_denies_llama70b():
    assert _allow(_claims("basic"), "llama-70b") is False


def test_premium_allows_llama8b():
    assert _allow(_claims("premium"), "llama-8b") is True


def test_premium_allows_llama70b():
    assert _allow(_claims("premium"), "llama-70b") is True


def test_research_allows_llama8b():
    assert _allow(_claims("research"), "llama-8b") is True


def test_research_allows_llama70b():
    assert _allow(_claims("research"), "llama-70b") is True


def test_unknown_role_denied():
    assert _allow(_claims("admin"), "llama-8b") is False


def test_missing_init_data_claims_denied():
    assert _allow({}, "llama-8b") is False


def test_missing_role_denied():
    claims = {"init_data_claims": {}}
    assert _allow(claims, "llama-8b") is False


def test_any_role_denies_unconfigured_model():
    assert _allow(_claims("premium"), "llama-405b") is False


def test_default_deny_with_empty_input():
    assert _allow({}, "") is False


# ── TDX measurement override ─────────────────────────────────────────────────

def test_tdx_correct_measurement_allows_research_model():
    claims = {
        "tee_type": "tdx",
        "measurement": "replace-with-your-mr-td",
    }
    assert _allow(claims, "llama-70b") is True


def test_tdx_wrong_measurement_denied():
    claims = {
        "tee_type": "tdx",
        "measurement": "wrong-measurement",
    }
    assert _allow(claims, "llama-70b") is False


def test_tdx_correct_measurement_denies_unconfigured_model():
    claims = {
        "tee_type": "tdx",
        "measurement": "replace-with-your-mr-td",
    }
    assert _allow(claims, "llama-405b") is False


def test_tdx_rule_requires_tee_type_claim():
    claims = {"measurement": "replace-with-your-mr-td"}
    assert _allow(claims, "llama-70b") is False
