#!/usr/bin/env python3
"""
Demo client — full TEE workload journey:
  attest → obtain scoped credentials → call model endpoint

Runs six scenarios (happy paths + failure cases) against a live demo stack.
"""
import base64
import json
import subprocess
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwcrypto import jwe as jwejwe
from jwcrypto import jwk

KBS_URL = "http://kbs:8080"
TEE_KEY_PATH = "/keys/tee.key"
PLUGIN_KEY_PATH = "/keys/plugin-token.key"

SEP = "━" * 50


def setup_kbs_policy() -> None:
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


def attest() -> str:
    print("  Attesting to KBS...")
    result = subprocess.run(
        ["kbs-client", "--url", KBS_URL, "attest", "--tee-key-file", TEE_KEY_PATH],
        capture_output=True,
        text=True,
        check=True,
    )
    token = result.stdout.strip()
    print(f"  KBS token   : {token[:40]}...")
    return token


def make_plugin_jwt(role: str) -> str:
    with open(PLUGIN_KEY_PATH, "rb") as f:
        key = load_pem_private_key(f.read(), None)
    return pyjwt.encode(
        {"role": role, "sub": "demo-tee", "exp": int(time.time()) + 300},
        key,
        algorithm="RS256",
    )


def call_plugin(model: str, plugin_jwt: str, kbs_token: str, tee_key) -> tuple[int, dict | None]:
    url = f"{KBS_URL}/kbs/v0/external/ai-gatekeeper/models/{model}"
    print(f"  Plugin call : POST /kbs/v0/external/ai-gatekeeper/models/{model}")
    with httpx.Client(timeout=15) as client:
        r = client.post(
            url,
            json={"token": plugin_jwt},
            headers={"Authorization": f"Bearer {kbs_token}"},
        )
    if r.status_code != 200:
        print(f"  Plugin      : {r.status_code}  {r.text.strip()}")
        return r.status_code, None
    tok = jwejwe.JWE()
    tok.deserialize(r.text.strip(), tee_key)
    payload = json.loads(tok.payload)
    print(f"  Plugin      : 200 OK  endpoint={payload['endpoint']}  token={payload['access_token'][:40]}...")
    return 200, payload


def call_model(endpoint: str, access_token: str) -> tuple[int, str]:
    url = f"{endpoint}/v1/chat/completions"
    print(f"  Model call  : POST {url}")
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

    print("Loading TEE key and generating plugin JWTs...")
    with open(TEE_KEY_PATH, "rb") as f:
        tee_key = jwk.JWK.from_pem(f.read())

    kbs_token = attest()
    jwt_basic = make_plugin_jwt("basic")
    jwt_premium = make_plugin_jwt("premium")

    # ── Scenario 1: premium role → llama-70b ──────────────────────────────
    banner("Scenario 1: Happy path — premium role → llama-70b")
    status, payload = call_plugin("llama-70b", jwt_premium, kbs_token, tee_key)
    token_70b = None
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        show_result(model_status == 200)
        token_70b = payload["access_token"]
    else:
        show_result(False)

    # ── Scenario 2: basic role → llama-8b ────────────────────────────────
    banner("Scenario 2: Happy path — basic role → llama-8b")
    status, payload = call_plugin("llama-8b", jwt_basic, kbs_token, tee_key)
    token_8b = None
    if payload:
        model_status, _ = call_model(payload["endpoint"], payload["access_token"])
        show_result(model_status == 200)
        token_8b = payload["access_token"]
    else:
        show_result(False)

    # ── Scenario 3: basic role denied llama-70b ───────────────────────────
    banner("Scenario 3: Policy deny — basic role requests llama-70b")
    print("  (KBS returns 401; plugin internally returns 403 policy deny)")
    status, _ = call_plugin("llama-70b", jwt_basic, kbs_token, tee_key)
    show_result(status == 401)

    # ── Scenario 4: unknown model ─────────────────────────────────────────
    banner("Scenario 4: Unknown model — plugin returns 404 (KBS→401)")
    status, _ = call_plugin("llama-999", jwt_premium, kbs_token, tee_key)
    show_result(status == 401)

    # ── Scenario 5: tampered access token direct to model endpoint ────────
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

    # ── Scenario 6: wrong scope direct to model endpoint ──────────────────
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
