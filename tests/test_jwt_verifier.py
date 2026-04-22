import datetime
import time

import jwt as pyjwt
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key as ec_key
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import NameOID

from ai_gatekeeper.jwt_verifier import JwtVerifier


@pytest.fixture(scope="module")
def rsa_key():
    return generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ec_cert_and_key(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("certs")
    key = ec_key(SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, str(cert_path)


def _rsa_cert_and_key(tmp_path):
    key = generate_private_key(65537, 2048, default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, str(cert_path)


def test_valid_token_returns_claims(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    token = pyjwt.encode({"role": "basic", "sub": "tee-1", "aud": "kbs", "exp": int(time.time()) + 300}, key, algorithm="RS256")
    claims = JwtVerifier.from_cert(cert_path, audience="kbs").verify(token)
    assert claims["role"] == "basic"
    assert claims["sub"] == "tee-1"


def test_expired_token_raises(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    token = pyjwt.encode({"sub": "tee-1", "exp": int(time.time()) - 1}, key, algorithm="RS256")
    with pytest.raises(Exception):
        JwtVerifier.from_cert(cert_path, audience="").verify(token)


def test_wrong_audience_raises(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    token = pyjwt.encode({"sub": "tee-1", "aud": "other", "exp": int(time.time()) + 300}, key, algorithm="RS256")
    with pytest.raises(Exception):
        JwtVerifier.from_cert(cert_path, audience="kbs").verify(token)


def test_empty_audience_skips_aud_check(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    token = pyjwt.encode({"sub": "tee-1", "aud": "any-value", "exp": int(time.time()) + 300}, key, algorithm="RS256")
    result = JwtVerifier.from_cert(cert_path, audience="").verify(token)
    assert result["sub"] == "tee-1"


def test_from_cert_verifies_ec_token(ec_cert_and_key):
    key, cert_path = ec_cert_and_key
    token = pyjwt.encode({"sub": "tee-1", "exp": int(time.time()) + 300}, key, algorithm="ES256")
    claims = JwtVerifier.from_cert(cert_path, audience="").verify(token)
    assert claims["sub"] == "tee-1"


def test_from_cert_rejects_tampered_token(ec_cert_and_key):
    key, cert_path = ec_cert_and_key
    token = pyjwt.encode({"sub": "tee-1", "exp": int(time.time()) + 300}, key, algorithm="ES256")
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + "TAMPER" + "." + parts[2]
    with pytest.raises(Exception):
        JwtVerifier.from_cert(cert_path, audience="").verify(tampered)


def test_leeway_accepts_recently_expired_token(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    # Token expired 5 seconds ago — should pass with 10-second leeway
    token = pyjwt.encode(
        {"sub": "tee-1", "exp": int(time.time()) - 5},
        key,
        algorithm="RS256",
    )
    claims = JwtVerifier.from_cert(cert_path, audience="", leeway_seconds=10).verify(token)
    assert claims["sub"] == "tee-1"


def test_leeway_rejects_long_expired_token(tmp_path):
    key, cert_path = _rsa_cert_and_key(tmp_path)
    # Token expired 30 seconds ago — should fail even with 10-second leeway
    token = pyjwt.encode(
        {"sub": "tee-1", "exp": int(time.time()) - 30},
        key,
        algorithm="RS256",
    )
    with pytest.raises(Exception):
        JwtVerifier.from_cert(cert_path, audience="", leeway_seconds=10).verify(token)
