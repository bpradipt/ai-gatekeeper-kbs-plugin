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


def _handler(*, allow=True, token_valid=True, kc_token="tok"):
    cfg = MagicMock()
    cfg.models = {
        "llama-8b": ModelConfig(endpoint="https://llama-8b/", scope="model:llama-8b")
    }

    verifier = MagicMock()
    if token_valid:
        verifier.verify.return_value = {"role": "basic", "sub": "tee-1"}
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
    # verify the handler wired the right values through to each dependency
    h._verifier.verify.assert_called_once_with("jwt")
    h._rego.allow.assert_awaited_once_with({"role": "basic", "sub": "tee-1"}, "llama-8b")
    h._kc.get_token.assert_awaited_once_with("model:llama-8b")


@pytest.mark.asyncio
async def test_invalid_token_returns_401():
    h = _handler(token_valid=False)
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 401
    # pipeline must stop after JWT failure — policy and upstream never reached
    h._verifier.verify.assert_called_once_with("jwt")
    h._rego.allow.assert_not_awaited()
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_policy_deny_returns_403():
    h = _handler(allow=False)
    resp = await h.handle(_request("llama-8b"))
    assert resp.status_code == 403
    # policy must be evaluated with the verified claims and the requested model
    h._rego.allow.assert_awaited_once_with({"role": "basic", "sub": "tee-1"}, "llama-8b")
    # upstream must not be reached on deny
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_model_returns_404():
    h = _handler()
    resp = await h.handle(_request("llama-405b"))
    assert resp.status_code == 404
    # policy must be checked before model existence (correct ordering)
    h._rego.allow.assert_awaited_once_with({"role": "basic", "sub": "tee-1"}, "llama-405b")
    # upstream must not be reached for an unconfigured model
    h._kc.get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_token_returns_400():
    h = _handler()
    req = PluginRequest(body=b"{}", path=["models", "llama-8b"], method="POST")
    resp = await h.handle(req)
    assert resp.status_code == 400
    # pipeline must stop before JWT verification on a malformed request
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
    # policy and upstream were both attempted before the upstream failure
    h._rego.allow.assert_awaited_once_with({"role": "basic", "sub": "tee-1"}, "llama-8b")
    h._kc.get_token.assert_awaited_once_with("model:llama-8b")


@pytest.mark.asyncio
async def test_missing_model_in_path_returns_400():
    h = _handler()
    req = PluginRequest(body=json.dumps({"token": "jwt"}).encode(), path=["models"], method="POST")
    resp = await h.handle(req)
    assert resp.status_code == 400
    h._verifier.verify.assert_not_called()
    h._rego.allow.assert_not_awaited()


# The two tests below verify KBS plugin SDK contract, not handler business logic.
# GatekeeperHandler does not override these methods; the assertions document the
# expected defaults from PluginHandler so an accidental override would break them.
@pytest.mark.asyncio
async def test_validate_auth_returns_false():
    assert await _handler().validate_auth(ValidateAuthRequest()) is False


@pytest.mark.asyncio
async def test_needs_encryption_returns_true():
    assert await _handler().needs_encryption(NeedsEncryptionRequest()) is True
