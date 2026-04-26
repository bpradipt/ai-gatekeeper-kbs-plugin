# ai_gatekeeper/ear_normalizer.py
"""
EAR (Entity Attestation Result) JWT claim normalizer.

The KBS attestation service produces JWTs in EAR format (eat_profile:
"tag:github.com,2024:confidential-containers/Trustee"). This module
extracts the attestation-relevant fields and exposes them under a flat,
stable interface that Rego policies can query without knowing the EAR
structure.

Normalized output fields (the operator contract):
  tee_type         str | None   TEE platform: "sample" | "tdx" | "snp" | "sgx" | ...
  ear_status       str | None   EAR verdict: "affirming" | "warning" | "contraindicated"
  init_data_hash   str | None   base64url SHA-256 of the initdata blob (from the hardware
                                register: mr_config_id on TDX, hostdata on SNP, PCR[8] on
                                vTPM). None if no initdata was provided.
  init_data_claims dict | None  Parsed content of the initdata TOML, present only when the
                                client passes the initdata plaintext to KBS at attestation
                                time. Top-level key=value pairs (e.g. role) appear directly;
                                config files in the [data] section appear under their
                                filenames (e.g. "aa.toml", "cdh.toml"). Example:
                                  init_data_claims["role"] == "basic"
                                Works identically on sample TEE, TDX, SNP, and vTPM.
  measurement      str | None   Primary measurement register, TEE-type-specific:
                                  sample → launch_digest
                                  tdx    → mr_td   (verify path against real TDX EAR)
                                  snp    → measurement
                                  sgx    → mrenclave
                                None for unknown TEE types.
  debug            bool | None  debug mode flag from TEE evidence; None if absent.

All fields default to None on parse error — a malformed EAR payload causes
deny (no init_data_claims match in Rego).
"""

_EXCLUDED_EVIDENCE_KEYS = frozenset({
    "report_data",
    "init_data",
    "init_data_claims",
    "runtime_data_claims",
})

# Maps TEE type name → field name for the primary measurement register.
# Add entries here as new TEE types are validated against real EAR output.
_MEASUREMENT_KEY: dict[str, str] = {
    "sample": "launch_digest",
    "tdx": "mr_td",        # verify against a live TDX EAR token
    "snp": "measurement",
    "sgx": "mrenclave",
}


def normalize_ear_claims(ear_claims: dict) -> dict:
    """Return a flat claims dict from a raw EAR JWT payload."""
    _empty = {
        "tee_type": None,
        "ear_status": None,
        "init_data_hash": None,
        "init_data_claims": None,
        "measurement": None,
        "debug": None,
    }
    try:
        cpu0 = ear_claims.get("submods", {}).get("cpu0", {})
        if not isinstance(cpu0, dict):
            return _empty

        evidence = cpu0.get("ear.veraison.annotated-evidence", {})
        if not isinstance(evidence, dict):
            return _empty

        tee_type = next(
            (k for k in evidence if k not in _EXCLUDED_EVIDENCE_KEYS),
            None,
        )

        tee_ev = evidence.get(tee_type, {}) if tee_type else {}
        measurement_key = _MEASUREMENT_KEY.get(tee_type) if tee_type else None

        return {
            "tee_type": tee_type,
            "ear_status": cpu0.get("ear.status"),
            "init_data_hash": evidence.get("init_data"),
            "init_data_claims": evidence.get("init_data_claims"),
            "measurement": tee_ev.get(measurement_key) if measurement_key else None,
            "debug": tee_ev.get("debug"),
        }
    except Exception:
        return _empty
