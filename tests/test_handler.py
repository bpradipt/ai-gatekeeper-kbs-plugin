# tests/test_handler.py
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from kbs_plugin_sdk.plugin.plugin_pb2 import (
    NeedsEncryptionRequest,
    PluginRequest,
    ValidateAuthRequest,
)

from ai_gatekeeper.config import ModelConfig
from ai_gatekeeper.handler import GatekeeperHandler

# Minimal EAR JWT payload that normalize_ear_claims can process.
_FAKE_EAR = {
    "submods": {
        "cpu0": {
            "ear.status": "affirming",
            "ear.veraison.annotated-evidence": {
                "sample": {"launch_digest": "abcde", "debug": False},
                "init_data": "IWjlrrHiZjz0SmFAWXDdSbqZcnLytZIOVGNgYJzv4b8",
                "init_data_claims": {
                    "aa.toml": {"extra": {"role": "basic"}}
                },
            },
        }
    }
}

# What normalize_ear_claims produces from _FAKE_EAR.
_NORMALIZED = {
    "tee_type": "sample",
    "ear_status": "affirming",
    "init_data_hash": "IWjlrrHiZjz0SmFAWXDdSbqZcnLytZIOVGNgYJzv4b8",
    "init_data_claims": {"aa.toml": {"extra": {"role": "basic"}}},
    "measurement": "abcde",
    "debug": False,
}


def _handler(*, allow=True, token_valid=True, kc_token="tok"):
    cfg = MagicMock()
    cfg.models = {
        "llama-8b": ModelConfig(endpoint="https://llama-8b/", scope="model:llama-8b")
    }

    verifier = MagicMock()
    if token_valid:
        verifier.verify.return_value = _FAKE_EAR
    else:
        verifier.verify.side_effect = Exception("invalid token")

    rego = MagicMock()
    rego.allow = AsyncMock(return_value=allow)

    kc = MagicMock()
    kc.get_token = AsyncMock(return_value=kc_token)

    return GatekeeperHandler(cfg, verifier, rego, kc)


def _request(model: str, body: bytes | None = None) -> PluginRequest:
    if body is None:
        body = json.dumps({"token": "jwt"}).encode()
    return PluginRequest(body=body, path=["models", model], method="POST")


@pytest.mark.asyncio
async def test_allowed_returns_endpoint_and_token():
    h = _handler()
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["access_token"] == "tok"
    assert body["endpoint"] == "https://llama-8b/"
    h._verifier.verify.assert_called_once_with("jwt")
    # rego receives the normalized EAR claims, not the raw EAR payload
    h._rego.allow.assert_awaited_once_with(_NORMALIZED, "llama-8b")
    h._kc.get_token.assert_awaited_once_with("model:llama-8b")


@pytest.mark.asyncio
async def test_invalid_token_returns_401():
    h = _handler(token_valid=False)
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 401
    h._verifier.verify.assert_called_once_with("jwt")
    h._rego.allow.assert_not_awaited()
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_policy_deny_returns_403():
    h = _handler(allow=False)
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 403
    h._rego.allow.assert_awaited_once_with(_NORMALIZED, "llama-8b")
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_model_returns_404():
    h = _handler()
    resp = await h.handle(_request("llama-405b"))
    assert resp.status_code == 404
    h._rego.allow.assert_awaited_once_with(_NORMALIZED, "llama-405b")
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_token_returns_400():
    h = _handler()
    req = PluginRequest(body=b"{}", path=["models", "llama-8b"], method="POST")
    resp = await h.handle(req)
    assert resp.status_code == 400
    h._verifier.verify.assert_not_called()
    h._rego.allow.assert_not_awaited()


@pytest.mark.asyncio
async def test_bad_json_returns_400():
    h = _handler()
    req = PluginRequest(body=b"not-json", path=["models", "llama-8b"], method="POST")
    resp = await h.handle(req)
    assert resp.status_code == 400
    h._verifier.verify.assert_not_called()
    h._rego.allow.assert_not_awaited()


@pytest.mark.asyncio
async def test_keycloak_failure_returns_502():
    h = _handler()
    h._kc.get_token = AsyncMock(side_effect=Exception("kc down"))
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 502
    h._rego.allow.assert_awaited_once_with(_NORMALIZED, "llama-8b")
    h._kc.get_token.assert_awaited_once_with("model:llama-8b")


@pytest.mark.asyncio
async def test_missing_model_in_path_returns_400():
    h = _handler()
    req = PluginRequest(body=json.dumps({"token": "jwt"}).encode(), path=["models"], method="POST")
    resp = await h.handle(req)
    assert resp.status_code == 400
    h._verifier.verify.assert_not_called()
    h._rego.allow.assert_not_awaited()


@pytest.mark.asyncio
async def test_validate_auth_returns_false():
    assert await _handler().validate_auth(ValidateAuthRequest()) is False


@pytest.mark.asyncio
async def test_needs_encryption_returns_true():
    assert await _handler().needs_encryption(NeedsEncryptionRequest()) is True
