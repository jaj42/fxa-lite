"""RS256 JWTs, verified against openssl rather than against our own signer."""

import json
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from fxa_lite.crypto import jose

KEY_PEM = Path(__file__).resolve().parent / "vectors" / "signing-key.pem"
KID = "20170316-bb501dcb"


@pytest.fixture(scope="module")
def key():
    return serialization.load_pem_private_key(KEY_PEM.read_bytes(), password=None)


def test_signature_is_pkcs1_v15_over_the_signing_input(key, tmp_path) -> None:
    token = jose.sign_jwt({"sub": "abc"}, key, kid=KID)
    header, payload, signature = token.split(".")

    signing_input = tmp_path / "input"
    signing_input.write_bytes(f"{header}.{payload}".encode())
    expected = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(KEY_PEM), str(signing_input)],
        capture_output=True,
        check=True,
    ).stdout
    assert jose.b64u_decode(signature) == expected


def test_header_names_the_algorithm_and_key(key) -> None:
    token = jose.sign_jwt({"sub": "abc"}, key, kid=KID, typ="at+JWT")
    assert jose.decode_jwt_header(token) == {"alg": "RS256", "typ": "at+JWT", "kid": KID}


def test_default_type_is_plain_jwt(key) -> None:
    assert jose.decode_jwt_header(jose.sign_jwt({}, key, kid=KID))["typ"] == "JWT"


def test_segments_are_compact_json(key) -> None:
    # A JWT with whitespace in its JSON verifies fine but is needlessly large,
    # and any change to the encoding changes every signature.
    _, payload, _ = jose.sign_jwt({"a": 1, "b": 2}, key, kid=KID).split(".")
    assert jose.b64u_decode(payload) == b'{"a":1,"b":2}'


def test_verify_returns_the_claims(key) -> None:
    claims = {"sub": "abc", "scope": "profile openid", "exp": int(time.time()) + 60}
    token = jose.sign_jwt(claims, key, kid=KID)
    assert jose.verify_jwt(token, key.public_key()) == claims


def test_verify_selects_the_key_by_kid(key) -> None:
    token = jose.sign_jwt({"sub": "abc"}, key, kid=KID)
    assert jose.verify_jwt(token, {KID: key.public_key()})["sub"] == "abc"

    with pytest.raises(jose.JWTError, match="no signing key"):
        jose.verify_jwt(token, {"someone-elses-kid": key.public_key()})


def test_verify_rejects_a_tampered_payload(key) -> None:
    header, payload, signature = jose.sign_jwt({"sub": "abc"}, key, kid=KID).split(".")
    forged = jose.b64u_encode(json.dumps({"sub": "admin"}).encode())
    with pytest.raises(jose.JWTError, match="signature"):
        jose.verify_jwt(f"{header}.{forged}.{signature}", key.public_key())


def test_verify_rejects_another_key(key) -> None:
    token = jose.sign_jwt({"sub": "abc"}, key, kid=KID)
    with pytest.raises(jose.JWTError, match="signature"):
        jose.verify_jwt(token, jose.generate_signing_key().public_key())


def test_verify_rejects_an_unsigned_token(key) -> None:
    # `alg: none` is the classic JWT hole: we accept exactly one algorithm.
    header = jose.b64u_encode(b'{"alg":"none","typ":"JWT"}')
    payload = jose.b64u_encode(b'{"sub":"admin"}')
    with pytest.raises(jose.JWTError, match="algorithm"):
        jose.verify_jwt(f"{header}.{payload}.", key.public_key())


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "not-a-jwt"])
def test_verify_rejects_malformed_tokens(token, key) -> None:
    with pytest.raises(jose.JWTError):
        jose.verify_jwt(token, key.public_key())


def test_verify_enforces_expiry(key) -> None:
    expires = 1_700_000_000
    token = jose.sign_jwt({"exp": expires}, key, kid=KID)

    assert jose.verify_jwt(token, key.public_key(), now=expires - 1)["exp"] == expires
    with pytest.raises(jose.JWTError, match="expired"):
        jose.verify_jwt(token, key.public_key(), now=expires)
    assert jose.verify_jwt(token, key.public_key(), now=expires + 5, leeway=10)


def test_verify_accepts_a_token_without_expiry(key) -> None:
    assert jose.verify_jwt(jose.sign_jwt({"sub": "abc"}, key, kid=KID), key.public_key())


def test_jwk_round_trip_verifies(key) -> None:
    jwk = jose.private_key_to_jwk(key, kid=KID)
    token = jose.sign_jwt({"sub": "abc"}, jose.jwk_to_private_key(jwk), kid=jwk["kid"])
    public = jose.jwk_to_public_key(jose.public_jwk(jwk))
    assert jose.verify_jwt(token, {jwk["kid"]: public})["sub"] == "abc"
