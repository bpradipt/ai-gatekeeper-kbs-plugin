# tests/test_ear_normalizer.py
import pytest
from ai_gatekeeper.ear_normalizer import normalize_ear_claims

# ── helpers ──────────────────────────────────────────────────────────────────

def _ear(tee_type: str, tee_evidence: dict, *, init_data: str | None = None,
         ear_status: str = "affirming") -> dict:
    """Build a minimal EAR JWT payload dict for the given TEE type."""
    annotated = {tee_type: tee_evidence}
    if init_data is not None:
        annotated["init_data"] = init_data
    return {
        "submods": {
            "cpu0": {
                "ear.status": ear_status,
                "ear.veraison.annotated-evidence": annotated,
            }
        }
    }


# ── sample TEE ───────────────────────────────────────────────────────────────

def test_sample_tee_type():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": False})
    result = normalize_ear_claims(ear)
    assert result["tee_type"] == "sample"


def test_sample_measurement_is_launch_digest():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": False})
    result = normalize_ear_claims(ear)
    assert result["measurement"] == "abcde"


def test_sample_debug_flag():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": True})
    result = normalize_ear_claims(ear)
    assert result["debug"] is True


def test_ear_status_propagated():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": False},
               ear_status="warning")
    result = normalize_ear_claims(ear)
    assert result["ear_status"] == "warning"


def test_init_data_hash_present():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": False},
               init_data="IWjlrrHiZjz0SmFAWXDdSbqZcnLytZIOVGNgYJzv4b8")
    result = normalize_ear_claims(ear)
    assert result["init_data_hash"] == "IWjlrrHiZjz0SmFAWXDdSbqZcnLytZIOVGNgYJzv4b8"


def test_init_data_hash_absent_is_none():
    ear = _ear("sample", {"launch_digest": "abcde", "debug": False})
    result = normalize_ear_claims(ear)
    assert result["init_data_hash"] is None


def test_debug_absent_is_none():
    ear = _ear("sample", {"launch_digest": "abcde"})
    result = normalize_ear_claims(ear)
    assert result["debug"] is None


# ── tdx TEE ──────────────────────────────────────────────────────────────────

def test_tdx_tee_type():
    ear = _ear("tdx", {"mr_td": "deadbeef", "debug": False})
    result = normalize_ear_claims(ear)
    assert result["tee_type"] == "tdx"


def test_tdx_measurement_is_mr_td():
    ear = _ear("tdx", {"mr_td": "deadbeef", "debug": False})
    result = normalize_ear_claims(ear)
    assert result["measurement"] == "deadbeef"


# ── snp TEE ──────────────────────────────────────────────────────────────────

def test_snp_measurement_is_measurement_field():
    ear = _ear("snp", {"measurement": "cafebabe"})
    result = normalize_ear_claims(ear)
    assert result["tee_type"] == "snp"
    assert result["measurement"] == "cafebabe"


# ── excluded keys not treated as TEE type ────────────────────────────────────

def test_excluded_keys_not_detected_as_tee():
    # annotated-evidence contains only shared/excluded keys — no TEE sub-object
    ear = {
        "submods": {
            "cpu0": {
                "ear.status": "affirming",
                "ear.veraison.annotated-evidence": {
                    "report_data": "xyz",
                    "init_data": "abc",
                    "init_data_claims": {},
                    "runtime_data_claims": {},
                }
            }
        }
    }
    result = normalize_ear_claims(ear)
    assert result["tee_type"] is None
    assert result["measurement"] is None


# ── graceful degradation ──────────────────────────────────────────────────────

def test_empty_dict_returns_all_none():
    result = normalize_ear_claims({})
    assert result == {
        "tee_type": None,
        "ear_status": None,
        "init_data_hash": None,
        "measurement": None,
        "debug": None,
    }


def test_malformed_submods_returns_all_none():
    result = normalize_ear_claims({"submods": "not-a-dict"})
    assert result == {
        "tee_type": None,
        "ear_status": None,
        "init_data_hash": None,
        "measurement": None,
        "debug": None,
    }
