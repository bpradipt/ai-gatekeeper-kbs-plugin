import pytest
from pydantic import ValidationError

from ai_gatekeeper.config import Config

VALID = """
jwt_verification:
  token_cert_path: /tmp/cert.pem
  audience: kbs
  leeway_seconds: 10
keycloak:
  url: https://kc
  realm: ai-models
  client_id: gk
  client_secret_path: /tmp/secret
models:
  llama-8b:
    endpoint: https://llama-8b/
    scope: model:llama-8b
opa_url: http://localhost:8181
server:
  address: "0.0.0.0:50051"
"""


def test_valid_config(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text(VALID)
    cfg = Config.from_yaml(str(f))
    assert cfg.keycloak.realm == "ai-models"
    assert "llama-8b" in cfg.models
    assert cfg.models["llama-8b"].scope == "model:llama-8b"
    assert cfg.opa_url == "http://localhost:8181"
    assert cfg.jwt_verification.leeway_seconds == 10


def test_missing_required_field(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("keycloak:\n  url: https://kc\n")
    with pytest.raises(ValidationError):
        Config.from_yaml(str(f))


def test_server_default_address(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text(VALID.replace('  address: "0.0.0.0:50051"\n', ""))
    cfg = Config.from_yaml(str(f))
    assert cfg.server.address == "0.0.0.0:50051"
