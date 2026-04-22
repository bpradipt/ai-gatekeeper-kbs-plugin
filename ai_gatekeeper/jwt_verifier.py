import datetime
import logging

from cryptography.x509 import load_pem_x509_certificate
from jwt import decode

logger = logging.getLogger(__name__)


class JwtVerifier:
    def __init__(self, public_key, audience: str = "", leeway_seconds: int = 0) -> None:
        self._public_key = public_key
        self._audience = audience
        self._leeway = datetime.timedelta(seconds=leeway_seconds)

    @classmethod
    def from_cert(cls, cert_path: str, audience: str = "", leeway_seconds: int = 0) -> "JwtVerifier":
        with open(cert_path, "rb") as f:
            public_key = load_pem_x509_certificate(f.read()).public_key()
        return cls(public_key, audience, leeway_seconds)

    def verify(self, token: str) -> dict:
        if not self._audience:
            logger.warning("audience validation is disabled — set jwt_verification.audience in config")
        kwargs: dict = {"algorithms": ["RS256", "ES256"], "leeway": self._leeway}
        if self._audience:
            kwargs["audience"] = self._audience
        else:
            kwargs["options"] = {"verify_aud": False}
        return decode(token, self._public_key, **kwargs)
