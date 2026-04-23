import json
import logging

from kbs_plugin_sdk import (
    PluginHandler,
    PluginRequest,
    PluginResponse,
)

from ai_gatekeeper.config import Config
from ai_gatekeeper.ear_normalizer import normalize_ear_claims
from ai_gatekeeper.jwt_verifier import JwtVerifier
from ai_gatekeeper.keycloak_client import KeycloakClient
from ai_gatekeeper.rego_evaluator import RegoEvaluator

logger = logging.getLogger(__name__)


class GatekeeperHandler(PluginHandler):
    def __init__(
        self,
        config: Config,
        verifier: JwtVerifier,
        rego: RegoEvaluator,
        kc: KeycloakClient,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._rego = rego
        self._kc = kc

    async def handle(self, request: PluginRequest) -> PluginResponse:
        if len(request.path) < 2 or not request.path[1]:
            logger.warning("rejected: missing model in path")
            return PluginResponse(body=b"missing model in path", status_code=400)

        model_name = request.path[1]

        try:
            body = json.loads(request.body)
            token = body["token"]
        except (json.JSONDecodeError, KeyError):
            logger.warning("model=%s rejected: missing or malformed token field", model_name)
            return PluginResponse(body=b"missing token", status_code=400)

        try:
            ear_claims = self._verifier.verify(token)
        except Exception as exc:
            logger.warning("model=%s rejected: token verification failed: %s", model_name, exc)
            return PluginResponse(body=b"invalid token", status_code=401)

        # Flatten EAR structure into the documented operator-facing claims dict.
        # Rego policy receives only these fields — see ear_normalizer.py for the
        # full field reference and TEE-type-specific source paths.
        normalized = normalize_ear_claims(ear_claims)
        subject = normalized.get("tee_type") or "<unknown-tee>"

        if not await self._rego.allow(normalized, model_name):
            logger.info("decision=deny tee=%s model=%s reason=policy", subject, model_name)
            return PluginResponse(body=b"access denied", status_code=403)

        model = self._config.models.get(model_name)
        if model is None:
            logger.warning(
                "decision=deny tee=%s model=%s reason=unknown-model (policy allowed but model not in config)",
                subject, model_name,
            )
            return PluginResponse(body=b"unknown model", status_code=404)

        try:
            access_token = await self._kc.get_token(model.scope)
        except Exception as exc:
            logger.error("decision=error tee=%s model=%s reason=upstream: %s", subject, model_name, exc)
            return PluginResponse(body=b"upstream error", status_code=502)

        logger.info("decision=allow tee=%s model=%s endpoint=%s", subject, model_name, model.endpoint)
        out = json.dumps({"endpoint": model.endpoint, "access_token": access_token})
        return PluginResponse(body=out.encode(), status_code=200)
