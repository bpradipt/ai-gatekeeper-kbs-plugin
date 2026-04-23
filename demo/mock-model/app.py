import os

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

MODEL_NAME = os.environ["MODEL_NAME"]
JWKS_URL = os.environ.get(
    "KEYCLOAK_JWKS_URL",
    "http://keycloak:8080/realms/ai-models/protocol/openid-connect/certs",
)

jwks_client = jwt.PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300)
app = FastAPI()


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return PlainTextResponse("missing or invalid token", status_code=401)
    token = auth[len("Bearer "):]
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            options={"verify_aud": False},
        )
    except Exception:
        return PlainTextResponse("invalid token", status_code=401)
    if MODEL_NAME not in claims.get("scope", "").split():
        return PlainTextResponse("insufficient scope", status_code=403)
    return JSONResponse({
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "model": MODEL_NAME,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": f"Hello from {MODEL_NAME}! (demo response)",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
    })
