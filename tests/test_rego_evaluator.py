import json

import httpx
import pytest
import respx

from ai_gatekeeper.rego_evaluator import RegoEvaluator

OPA_BASE = "http://opa:8181"
OPA_ALLOW_URL = f"{OPA_BASE}/v1/data/ai_gatekeeper/allow"


@pytest.fixture
def rego():
    return RegoEvaluator(OPA_BASE)


@pytest.mark.asyncio
async def test_allow_returns_true_on_true_result(rego):
    with respx.mock:
        respx.post(OPA_ALLOW_URL).mock(
            return_value=httpx.Response(200, json={"result": True})
        )
        assert await rego.allow({"role": "basic"}, "llama-8b") is True


@pytest.mark.asyncio
async def test_deny_returns_false_on_false_result(rego):
    with respx.mock:
        respx.post(OPA_ALLOW_URL).mock(
            return_value=httpx.Response(200, json={"result": False})
        )
        assert await rego.allow({"role": "basic"}, "llama-70b") is False


@pytest.mark.asyncio
async def test_deny_when_result_key_absent(rego):
    # OPA returns {} when the rule is undefined — treat as deny
    with respx.mock:
        respx.post(OPA_ALLOW_URL).mock(
            return_value=httpx.Response(200, json={})
        )
        assert await rego.allow({"role": "basic"}, "llama-8b") is False


@pytest.mark.asyncio
async def test_deny_on_opa_server_error(rego):
    with respx.mock:
        respx.post(OPA_ALLOW_URL).mock(return_value=httpx.Response(500))
        assert await rego.allow({"role": "basic"}, "llama-8b") is False


@pytest.mark.asyncio
async def test_deny_on_opa_connection_refused(rego):
    with respx.mock:
        respx.post(OPA_ALLOW_URL).mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        assert await rego.allow({"role": "basic"}, "llama-8b") is False


@pytest.mark.asyncio
async def test_request_payload_contains_claims_and_model(rego):
    with respx.mock:
        route = respx.post(OPA_ALLOW_URL).mock(
            return_value=httpx.Response(200, json={"result": True})
        )
        await rego.allow({"role": "premium", "sub": "tee-1"}, "llama-70b")

    sent = json.loads(route.calls.last.request.content)
    assert sent["input"]["claims"] == {"role": "premium", "sub": "tee-1"}
    assert sent["input"]["model"] == "llama-70b"
