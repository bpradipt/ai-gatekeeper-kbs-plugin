#!/usr/bin/env python3
"""
Demo client — full TEE workload journey:
  attest (with initdata TOML) → obtain scoped credentials → call model endpoint

The body token sent to the plugin IS the KBS attestation JWT — the same token
used as the Bearer. No separate signing key is involved. Role is derived inside
the plugin from init_data_claims in the EAR attestation JWT.

Runs six scenarios (happy paths + failure cases) against a live demo stack.
"""
import json
import subprocess

import httpx
import jwt as pyjwt
from jwcrypto import jwe as jwejwe
from jwcrypto import jwk

KBS_URL = "http://kbs:8080"
TEE_KEY_PATH = "/keys/tee.key"


def _initdata(role: str) -> str:
    return f'''version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = """
[token_configs.kbs]
url = "{KBS_URL}"

[extra]
role = "{role}"
"""
'''


SEP = "━" * 50


def setup_kbs_policy() -> None:
    import base64
    policy = b"package policy\ndefault allow = true"
    encoded = base64.urlsafe_b64encode(policy).rstrip(b"=").decode()
    with httpx.Client(timeout=10) as client:
        r = client.post(
            f"{KBS_URL}/kbs/v0/resource-policy",
            json={"policy": encoded},
            headers={"Authorization": "Bearer dev-token"},
        )
        r.raise_for_status()
    print("  KBS resource policy set (allow-all).")


def banner(title: str) -> None:
    print(f"\n{SEP}\n{title}\n{SEP}")


def attest(role: str) -> str:
    """
    Run kbs-client attest with initdata carrying the given role.

    The initdata TOML is structured per the CoCo initdata spec (version 0.1.0).
    KBS parses the plaintext and exposes it as init_data_claims in the EAR JWT.
    The plugin's Rego policy reads the role from:
      init_data_claims["aa.toml"]["extra"]["role"]

    On real hardware (TDX/SNP), the initdata hash is cryptographically bound to
    the TEE measurement register — the workload cannot forge a different role
    after launch. On sample TEE (used here) the hash is not hardware-verified.
    """
    initdata = _initdata(role)
    cmd = ["kbs-client", "--url", KBS_URL, "attest", "--tee-key-file", TEE_KEY_PATH, initdata]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    token = result.stdout.strip()
    print(f"  KBS attestation token (role={role!r}): {token[:40]}...")
    print(f"  (proves TEE completed RCAR handshake; init_data_claims carry role)")
    return token


def call_plugin(model: str, kbs_token: str, tee_key) -> tuple[int, dict | None]:
    """
    Call the AI gatekeeper plugin via KBS.

    The KBS attestation JWT is used both as the Bearer token (KBS validates
    TEE attestation) and as the body token (plugin verifies and normalizes
    EAR claims, reads role from init_data_claims["aa.toml"]["extra"]["role"],
    fetches Keycloak token).
    """
    url = f"{KBS_URL}/kbs/v0/external/ai-gatekeeper/models/{model}"
    print(f"  Plugin call : POST /kbs/v0/external/ai-gatekeeper/models/{model}")
    with httpx.Client(timeout=15) as client:
        r = client.post(
            url,
            json={"token": kbs_token},
            headers={"Authorization": f"Bearer {kbs_token}"},
        )
    if r.status_code != 200:
        print(f"  Plugin      : {r.status_code}  {r.text.strip()}")
        return r.status_code, None
    tok = jwejwe.JWE()
    tok.deserialize(r.text.strip(), tee_key)
    payload = json.loads(tok.payload)
    kc_claims = pyjwt.decode(payload["access_token"], options={"verify_signature": False})
    kc_scope = kc_claims.get("scope", "(no scope claim)")
    print(f"  Plugin      : 200 OK (JWE-encrypted response, decrypted with TEE private key)")
    print(f"  Endpoint    : {payload['endpoint']}")
    print(f"  KC token    : {payload['access_token'][:40]}...")
    print(f"  (Keycloak access token issued to this TEE; scope={kc_scope!r})")
    return 200, payload


def call_model(endpoint: str, access_token: str) -> tuple[int, str]:
    url = f"{endpoint}/v1/chat/completions"
    print(f"  Model call  : POST {url}")
    print(f"  (using Keycloak access token as Bearer; model validates via JWKS)")
    with httpx.Client(timeout=10) as client:
        r = client.post(
            url,
            json={"model": "demo", "messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if r.status_code == 200:
        content = r.json()["choices"][0]["message"]["content"]
        print(f"  Model       : 200 OK  \"{content}\"")
    else:
        print(f"  Model       : {r.status_code}  {r.text.strip()}")
    return r.status_code, r.text


def show_result(ok: bool) -> None:
    print(f"  Result      : {'PASS' if ok else 'FAIL'}")


def main() -> None:
    print("Configuring KBS resource policy...")
    setup_kbs_policy()

    print("Loading TEE key...")
    with open(TEE_KEY_PATH, "rb") as f:
        tee_key = jwk.JWK.from_pem(f.read())

    print("Attesting to establish roles via initdata...")
    kbs_token_basic = attest("basic")
    kbs_token_premium = attest("premium")

    token_70b = None
    token_8b = None

    # ── Scenario 1: role=premium → llama-70b ──────────────────────────────────
    banner("Scenario 1: Happy path — role=premium → llama-70b")
    status, payload = call_plugin("llama-70b", kbs_token_premium, tee_key)
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        show_result(model_status == 200)
        token_70b = payload["access_token"]
    else:
        show_result(False)

    # ── Scenario 2: role=basic → llama-8b ─────────────────────────────────────
    banner("Scenario 2: Happy path — role=basic → llama-8b")
    status, payload = call_plugin("llama-8b", kbs_token_basic, tee_key)
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        show_result(model_status == 200)
        token_8b = payload["access_token"]
    else:
        show_result(False)

    # ── Scenario 3: role=basic denied llama-70b ───────────────────────────────
    banner("Scenario 3: Policy deny — role=basic requests llama-70b")
    print("  (KBS returns 401; plugin internally returns 403 policy deny)")
    status, _ = call_plugin("llama-70b", kbs_token_basic, tee_key)
    show_result(status == 401)

    # ── Scenario 4: unknown model ─────────────────────────────────────────────
    banner("Scenario 4: Unknown model — plugin returns 404 (KBS→401)")
    status, _ = call_plugin("llama-999", kbs_token_premium, tee_key)
    show_result(status == 401)

    # ── Scenario 5: tampered access token direct to model endpoint ────────────
    banner("Scenario 5: Tampered access token — direct call to model endpoint")
    print("  (Bypasses KBS; model validates token independently via JWKS)")
    if token_70b:
        chars = list(token_70b)
        chars[10] = "X" if chars[10] != "X" else "Y"
        tampered = "".join(chars)
        model_status, _ = call_model("http://llama-70b:8080", tampered)
        show_result(model_status == 401)
    else:
        print("  Skipped (no token from scenario 1)")
        show_result(False)

    # ── Scenario 6: wrong scope direct to model endpoint ──────────────────────
    banner("Scenario 6: Wrong scope — llama-8b token used against llama-70b endpoint")
    print("  (Bypasses KBS; model rejects token with mismatched scope)")
    if token_8b:
        model_status, _ = call_model("http://llama-70b:8080", token_8b)
        show_result(model_status == 403)
    else:
        print("  Skipped (no token from scenario 2)")
        show_result(False)

    print(f"\n{SEP}")
    print("Demo complete.")
    print(SEP)


if __name__ == "__main__":
    main()
