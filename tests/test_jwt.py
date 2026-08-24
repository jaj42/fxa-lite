"""RS256 JWTs, verified against RFC 7515 and openssl rather than our own signer."""

import hashlib
import hmac
import json
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from fxa_lite.crypto import jose
from vectors import load

KEY_PEM = Path(__file__).resolve().parent / "vectors" / "signing-key.pem"
KID = "20170316-bb501dcb"
RS256 = load("jose")["rs256"]


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


# --------------------------------------------------------------------------
# RFC 7515 appendix A.2 — the one RS256 known-answer test that is not ours.
# --------------------------------------------------------------------------


def test_verifies_the_rfc7515_appendix_a2_token() -> None:
    public = jose.jwk_to_public_key(RS256["private_jwk"])
    claims = jose.verify_jwt(RS256["token"], public, now=RS256["expires"] - 1)
    assert claims == RS256["claims"]


def test_reproduces_the_rfc7515_appendix_a2_signature() -> None:
    # PKCS#1 v1.5 is deterministic, so the RFC's signature is reproducible —
    # unlike PSS, where only verification could be pinned.
    private = jose.jwk_to_private_key(RS256["private_jwk"])
    signature = private.sign(
        RS256["signing_input"].encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    assert jose.b64u_encode(signature) == RS256["signature"]


def test_the_rfc7515_appendix_a2_token_has_expired_by_now() -> None:
    # exp is in 2011: without `now`, the vector must fail closed.
    with pytest.raises(jose.JWTError, match="expired"):
        jose.verify_jwt(RS256["token"], jose.jwk_to_public_key(RS256["private_jwk"]))


# --------------------------------------------------------------------------
# Hostile input. Everything below is what a JWT parser gets wrong.
# --------------------------------------------------------------------------


def test_verify_rejects_algorithm_confusion(key) -> None:
    """The classic: HS256 signed with the *public* key as the HMAC secret.

    A verifier that dispatches on the header's `alg` hands its public key to
    an HMAC, and the public key is public. We accept one algorithm, so the
    token dies at the header — but the test has to exist, because the bug is
    a one-line "improvement" away.
    """
    public = json.dumps(jose.public_jwk(jose.private_key_to_jwk(key, kid=KID))).encode()
    header = jose.b64u_encode(b'{"alg":"HS256","typ":"at+JWT"}')
    payload = jose.b64u_encode(b'{"sub":"admin"}')
    forged = hmac.new(public, f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()

    with pytest.raises(jose.JWTError, match="algorithm"):
        jose.verify_jwt(f"{header}.{payload}.{jose.b64u_encode(forged)}", key.public_key())


@pytest.mark.parametrize("claim", ["exp", "iat"])
@pytest.mark.parametrize("value", ['"1700000000"', "true", "null", "[1700000000]"])
def test_verify_rejects_a_non_numeric_time_claim(key, claim, value) -> None:
    # A string `exp` is not "no expiry": RFC 7519 §2 says NumericDate, and a
    # token that spells it any other way was not minted by us.
    token = _signed(key, f'{{"sub":"abc","{claim}":{value}}}')
    with pytest.raises(jose.JWTError, match=f"{claim} is not a number"):
        jose.verify_jwt(token, key.public_key())


@pytest.mark.parametrize(
    "payload", ["[1,2,3]", '"a string"', "42", "null"], ids=["array", "string", "number", "null"]
)
def test_verify_rejects_a_payload_that_is_not_an_object(key, payload) -> None:
    with pytest.raises(jose.JWTError, match="payload is not an object"):
        jose.verify_jwt(_signed(key, payload), key.public_key())


@pytest.mark.parametrize(
    "token",
    ["", ".", "..", "a.b.c.d.e", "a" * 100, "not-a-jwt.not-a-jwt.not-a-jwt"],
    ids=["empty", "one-dot", "two-dots", "five-segments", "no-dots", "garbage-segments"],
)
def test_verify_rejects_structural_nonsense(key, token) -> None:
    with pytest.raises(jose.JWTError):
        jose.verify_jwt(token, key.public_key())


def test_verify_rejects_a_header_that_is_not_an_object(key) -> None:
    with pytest.raises(jose.JWTError, match="header is not an object"):
        jose.verify_jwt(f"{jose.b64u_encode(b'[]')}.e30.", key.public_key())


def test_verify_rejects_a_signature_that_is_not_base64url(key) -> None:
    header, payload, _ = jose.sign_jwt({"sub": "abc"}, key, kid=KID).split(".")
    with pytest.raises(jose.JWTError, match="base64url"):
        jose.verify_jwt(f"{header}.{payload}.+/+/+/", key.public_key())


def test_an_oversized_token_is_refused_before_it_is_parsed(key) -> None:
    # The cap is the only bound on how much work an unauthenticated
    # `Authorization:` header can ask for, since nothing is verified yet.
    header = jose.b64u_encode(b'{"alg":"RS256","kid":"x","pad":"' + b"A" * 1_000_000 + b'"}')
    token = f"{header}.e30."
    with pytest.raises(jose.JWTError, match="longer than"):
        jose.verify_jwt(token, key.public_key())
    with pytest.raises(jose.JWTError, match="longer than"):
        jose.decode_jwt_header(token)


def test_the_size_cap_leaves_a_real_access_token_room(key) -> None:
    # Guards the cap from the other side: it has to be comfortably above what
    # we actually mint, or it becomes an outage the first time a scope is added.
    claims = {
        "sub": "a" * 32,
        "aud": "https://accounts.example.org/token/1.0/sync/1.5",
        "iss": "https://accounts.example.org",
        "client_id": "5882386c6d801776",
        "scope": " ".join(f"https://identity.mozilla.com/apps/scope-{i}" for i in range(10)),
        "exp": 2_000_000_000,
        "iat": 1_999_978_400,
        "jti": "b" * 32,
    }
    token = jose.sign_jwt(claims, key, kid=KID, typ="at+JWT")
    assert len(token) < jose.MAX_JWT_LENGTH // 4
    assert jose.verify_jwt(token, key.public_key(), now=1_999_978_500) == claims


def _signed(key, payload_json: str) -> str:
    """A structurally valid, correctly signed JWT with an arbitrary payload."""
    header = jose.b64u_encode(b'{"alg":"RS256","typ":"JWT","kid":"' + KID.encode() + b'"}')
    payload = jose.b64u_encode(payload_json.encode())
    signature = key.sign(
        f"{header}.{payload}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{header}.{payload}.{jose.b64u_encode(signature)}"
