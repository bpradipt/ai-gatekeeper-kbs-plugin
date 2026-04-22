import asyncio
import logging
import os

from kbs_plugin_sdk import PluginServer, TlsConfig

from ai_gatekeeper.config import Config
from ai_gatekeeper.handler import GatekeeperHandler
from ai_gatekeeper.jwt_verifier import JwtVerifier
from ai_gatekeeper.keycloak_client import KeycloakClient
from ai_gatekeeper.rego_evaluator import RegoEvaluator

logging.basicConfig(level=logging.INFO)


async def main() -> None:
    cfg = Config.from_yaml(os.environ.get("AI_GATEKEEPER_CONFIG", "config.yaml"))

    with open(cfg.keycloak.client_secret_path) as f:
        kc_secret = f.read().strip()

    jv_cfg = cfg.jwt_verification
    verifier = JwtVerifier.from_cert(
        jv_cfg.token_cert_path, jv_cfg.audience, jv_cfg.leeway_seconds
    )

    handler = GatekeeperHandler(
        config=cfg,
        verifier=verifier,
        rego=RegoEvaluator(cfg.opa_url),
        kc=KeycloakClient.from_config(
            cfg.keycloak.url,
            cfg.keycloak.realm,
            cfg.keycloak.client_id,
            kc_secret,
            cfg.keycloak.timeout_seconds,
        ),
    )

    server = PluginServer(handler).with_address(cfg.server.address)
    if cfg.server.tls:
        server = server.with_tls(
            TlsConfig.server_tls(cfg.server.tls.cert, cfg.server.tls.key)
        )
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
