"""JWK handling, checked against openssl rather than against ourselves."""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from fxa_lite.crypto import jose

VECTORS = Path(__file__).resolve().parent / "vectors"
KEY_PEM = VECTORS / "signing-key.pem"

# sha256 of `openssl rsa -in signing-key.pem -RSAPublicKey_out`, first 8 hex chars —
# the fingerprint half of the kid the reference server would give this key.
EXPECTED_FINGERPRINT = "bb501dcb"


@pytest.fixture(scope="module")
def key():
    return serialization.load_pem_private_key(KEY_PEM.read_bytes(), password=None)


def openssl(*args: str) -> bytes:
    return subprocess.run(args, capture_output=True, check=True).stdout


def test_b64u_roundtrip() -> None:
    for raw in (b"", b"\x00", b"\xff" * 32, bytes(range(256))):
        assert jose.b64u_decode(jose.b64u_encode(raw)) == raw


def test_b64u_uint_is_minimal_big_endian() -> None:
    # No leading zero byte, unlike a fixed-width encoding, and no padding.
    assert jose.b64u_uint(65537) == "AQAB"
    assert jose.b64u_uint(0) == "AA"
    assert jose.b64u_uint(255) == "_w"
    assert jose.uint_b64u(jose.b64u_uint(2**2047 + 1)) == 2**2047 + 1


def test_key_id_matches_openssl_fingerprint(key) -> None:
    pkcs1_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    assert pkcs1_pem == openssl("openssl", "rsa", "-in", str(KEY_PEM), "-RSAPublicKey_out")
    assert hashlib.sha256(pkcs1_pem).hexdigest()[:8] == EXPECTED_FINGERPRINT

    kid = jose.key_id(key.public_key(), now=datetime(2017, 3, 16, 5, 0, tzinfo=UTC))
    assert kid == f"20170316-{EXPECTED_FINGERPRINT}"


def test_key_id_defaults_to_today(key) -> None:
    kid = jose.key_id(key.public_key())
    assert kid == f"{datetime.now(UTC):%Y%m%d}-{EXPECTED_FINGERPRINT}"


def test_private_jwk_members_match_openssl(key) -> None:
    jwk = jose.private_key_to_jwk(key)

    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"].endswith(EXPECTED_FINGERPRINT)
    assert set(jwk) == {
        "kty", "kid", "alg", "use", "fxa-createdAt", "n", "e", "d", "p", "q", "dp", "dq", "qi",
    }

    modulus = openssl("openssl", "rsa", "-in", str(KEY_PEM), "-noout", "-modulus")
    expected_n = int(modulus.decode().strip().removeprefix("Modulus="), 16)
    assert jose.uint_b64u(jwk["n"]) == expected_n
    assert jose.uint_b64u(jwk["e"]) == 65537

    numbers = key.private_numbers()
    assert jose.uint_b64u(jwk["d"]) == numbers.d
    assert jose.uint_b64u(jwk["p"]) == numbers.p
    assert jose.uint_b64u(jwk["q"]) == numbers.q
    assert jose.uint_b64u(jwk["dp"]) == numbers.dmp1
    assert jose.uint_b64u(jwk["dq"]) == numbers.dmq1
    assert jose.uint_b64u(jwk["qi"]) == numbers.iqmp


def test_created_at_is_rounded_to_the_hour(key) -> None:
    created = jose.private_key_to_jwk(key)["fxa-createdAt"]
    assert created % 3600 == 0


def test_jwk_roundtrip_signs_and_verifies(key) -> None:
    jwk = jose.private_key_to_jwk(key)
    restored = jose.jwk_to_private_key(json.loads(json.dumps(jwk)))

    message = b"a JWT signing input, one day"
    signature = restored.sign(message, padding.PKCS1v15(), hashes.SHA256())
    jose.jwk_to_public_key(jose.public_jwk(jwk)).verify(
        signature, message, padding.PKCS1v15(), hashes.SHA256()
    )
    assert restored.private_numbers() == key.private_numbers()


def test_public_jwk_drops_every_private_member(key) -> None:
    jwk = jose.private_key_to_jwk(key)
    public = jose.public_jwk(jwk)

    assert set(public) == {"kty", "alg", "kid", "use", "n", "e", "fxa-createdAt"}
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(public)
    assert public["n"] == jwk["n"] and public["e"] == jwk["e"]


def test_generate_signing_key_is_2048_bit() -> None:
    generated = jose.generate_signing_key()
    assert generated.key_size == jose.MODULUS_BITS
    assert generated.public_key().public_numbers().e == jose.PUBLIC_EXPONENT


@pytest.mark.parametrize("bad", [{"kty": "EC", "n": "AA", "e": "AQAB"}, {"kty": "RSA"}])
def test_rejects_non_rsa_or_incomplete_jwk(bad) -> None:
    with pytest.raises(ValueError):
        jose.jwk_to_private_key(bad)
