from __future__ import annotations

import yaml
from pydantic import BaseModel, model_validator


class JwtConfig(BaseModel):
    token_cert_path: str
    audience: str  # required; set to "" to explicitly skip audience check (insecure, logs a warning)
    leeway_seconds: int = 10


class KeycloakConfig(BaseModel):
    url: str
    realm: str
    client_id: str
    client_secret_path: str
    timeout_seconds: int = 10


class ModelConfig(BaseModel):
    endpoint: str
    scope: str


class ServerTlsConfig(BaseModel):
    cert: str
    key: str


class ServerConfig(BaseModel):
    address: str = "0.0.0.0:50051"
    tls: ServerTlsConfig | None = None


class Config(BaseModel):
    jwt_verification: JwtConfig
    keycloak: KeycloakConfig
    models: dict[str, ModelConfig]
    opa_url: str
    server: ServerConfig = ServerConfig()

    @model_validator(mode="before")
    @classmethod
    def _default_server(cls, data: dict) -> dict:
        if isinstance(data, dict) and not data.get("server"):
            data["server"] = {}
        return data

    @classmethod
    def from_yaml(cls, path: str) -> Config:
        with open(path) as f:
            return cls(**yaml.safe_load(f))
