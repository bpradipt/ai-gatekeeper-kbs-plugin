import logging

import httpx

logger = logging.getLogger(__name__)


class RegoEvaluator:
    def __init__(self, opa_url: str) -> None:
        self._url = opa_url.rstrip("/") + "/v1/data/ai_gatekeeper/allow"

    async def allow(self, claims: dict, model: str) -> bool:
        payload = {"input": {"claims": claims, "model": model}}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(self._url, json=payload)
                r.raise_for_status()
                return r.json().get("result") is True
        except Exception as exc:
            logger.error("opa query failed url=%s: %s", self._url, exc)
            return False
