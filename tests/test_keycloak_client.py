import pytest
import httpx
import respx

from ai_gatekeeper.keycloak_client import KeycloakClient

TOKEN_URL = "https://kc/realms/ai-models/protocol/openid-connect/token"


@pytest.fixture
def kc():
    return KeycloakClient(TOKEN_URL, "gk", "secret")


@pytest.mark.asyncio
async def test_get_token_success(kc):
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok123"})
        )
        token = await kc.get_token("model:llama-8b")
    assert token == "tok123"


@pytest.mark.asyncio
async def test_get_token_raises_on_error(kc):
    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(401))
        with pytest.raises(httpx.HTTPStatusError):
            await kc.get_token("model:llama-8b")


def test_from_config_builds_correct_url():
    kc = KeycloakClient.from_config("https://kc", "ai-models", "gk", "secret")
    assert kc._token_url == TOKEN_URL


@pytest.mark.asyncio
async def test_get_token_sends_scope(kc):
    with respx.mock:
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        await kc.get_token("model:llama-70b")
    request_body = route.calls.last.request.content.decode()
    assert "model%3Allama-70b" in request_body or "model:llama-70b" in request_body
