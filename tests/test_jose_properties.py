"""Property tests over `crypto/jose.py`: the parsers, against input nobody chose.

The named negative tests in `test_jwt.py` and `test_jwe.py` are a list of ways
a JOSE parser is known to fail. This file asserts the invariant *behind* that
list, which is the part a list cannot cover: whatever arrives at `verify_jwt`
or `decrypt_jwe`, the only thing that comes back out is the claims, the
plaintext, or `JWTError`/`JWEError`.

That invariant is what the callers are written against. `oauth/routes.py`,
`profile/__init__.py` and `tokenserver/__init__.py` each turn `JWTError` into a
401; a `binascii.Error`, a `UnicodeDecodeError` or a `TypeError` escaping the
same call is a 500 with a traceback, on a route that takes its input from an
unauthenticated `Authorization:` header.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fxa_lite.crypto import jose

KEY_PEM = Path(__file__).resolve().parent / "vectors" / "signing-key.pem"
KID = "20170316-bb501dcb"


def _signing_key() -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(KEY_PEM.read_bytes(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


SIGNING_KEY = _signing_key()
RECIPIENT = ec.generate_private_key(ec.SECP256R1())

#: Key generation is far too slow to sit inside a hypothesis example, so both
#: keys are module-level and reused. Neither test mutates them.
SLOW_FIXTURES = settings(
    max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture]
)

#: Text that looks enough like a token to get past the shape checks and reach
#: the parsing, mixed with text that does not.
segment = st.one_of(
    st.text(alphabet="ABCXYZabcxyz0123456789-_=.", max_size=40),
    st.binary(max_size=32).map(jose.b64u_encode),
    st.dictionaries(st.text(max_size=8), st.integers() | st.text(max_size=8), max_size=4).map(
        lambda value: jose.b64u_encode(json.dumps(value).encode())
    ),
)
tokenish = st.one_of(
    st.text(max_size=200),
    st.lists(segment, min_size=1, max_size=6).map(".".join),
)


# --- JWT --------------------------------------------------------------------


@given(tokenish)
@SLOW_FIXTURES
def test_verify_jwt_raises_only_jwt_error(token: str) -> None:
    with contextlib.suppress(jose.JWTError):
        jose.verify_jwt(token, SIGNING_KEY.public_key())


@given(tokenish)
@SLOW_FIXTURES
def test_decode_jwt_header_raises_only_jwt_error(token: str) -> None:
    with contextlib.suppress(jose.JWTError):
        jose.decode_jwt_header(token)


@given(
    st.dictionaries(
        # Not the two claims `verify_jwt` reads: a generated `exp` is either a
        # non-number, which it is right to reject, or an expiry in the past,
        # which it is right to enforce. Both are checked deliberately below;
        # here they would only be an unreliable way of checking them.
        st.text(min_size=1, max_size=20).filter(lambda name: name not in ("exp", "iat")),
        st.text(max_size=40) | st.integers() | st.booleans() | st.none(),
        max_size=8,
    )
)
@SLOW_FIXTURES
def test_sign_then_verify_returns_the_claims(claims: dict) -> None:
    token = jose.sign_jwt(claims, SIGNING_KEY, kid=KID)
    assert jose.verify_jwt(token, {KID: SIGNING_KEY.public_key()}, now=0) == claims


@given(st.integers(min_value=0, max_value=2**31), st.integers(min_value=0, max_value=3600))
@SLOW_FIXTURES
def test_expiry_is_exactly_the_boundary(expires: int, leeway: int) -> None:
    token = jose.sign_jwt({"exp": expires}, SIGNING_KEY, kid=KID)
    public = SIGNING_KEY.public_key()
    assert jose.verify_jwt(token, public, now=expires + leeway - 1, leeway=leeway)
    with pytest.raises(jose.JWTError, match="expired"):
        jose.verify_jwt(token, public, now=expires + leeway, leeway=leeway)


@given(st.integers(min_value=0, max_value=2), st.integers(min_value=0, max_value=255))
@SLOW_FIXTURES
def test_no_single_byte_may_be_changed(segment_index: int, offset: int) -> None:
    """Flip one byte of one decoded segment; the token must stop verifying.

    Bytes rather than characters: the trailing base64url character of a segment
    carries unused bits, so two spellings can decode to the same bytes and a
    character-level mutation is allowed to be a no-op. A byte-level one is not.
    """
    parts = jose.sign_jwt({"sub": "abc"}, SIGNING_KEY, kid=KID).split(".")
    raw = bytearray(jose.b64u_decode(parts[segment_index]))
    index = offset % len(raw)
    raw[index] ^= 1 << (offset % 8)
    parts[segment_index] = jose.b64u_encode(bytes(raw))

    with pytest.raises(jose.JWTError):
        jose.verify_jwt(".".join(parts), SIGNING_KEY.public_key())


# --- JWE --------------------------------------------------------------------


@given(tokenish)
@SLOW_FIXTURES
def test_decrypt_jwe_raises_only_jwe_error(jwe: str) -> None:
    with contextlib.suppress(jose.JWEError):
        jose.decrypt_jwe(jwe, RECIPIENT)


@given(st.binary(max_size=4096), st.binary(max_size=64), st.binary(max_size=64))
@SLOW_FIXTURES
def test_ecdh_es_round_trips_any_plaintext(plaintext: bytes, apu: bytes, apv: bytes) -> None:
    jwe = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(RECIPIENT.public_key()), plaintext, apu=apu, apv=apv
    )
    assert jose.decrypt_jwe(jwe, RECIPIENT) == plaintext


@given(st.integers(min_value=0, max_value=4), st.integers(min_value=0, max_value=255))
@SLOW_FIXTURES
def test_no_single_byte_of_a_jwe_may_be_changed(segment_index: int, offset: int) -> None:
    parts = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(RECIPIENT.public_key()), b"a scoped key bundle"
    ).split(".")
    if not parts[segment_index]:  # the empty encrypted-key segment
        return
    raw = bytearray(jose.b64u_decode(parts[segment_index]))
    raw[offset % len(raw)] ^= 1 << (offset % 8)
    parts[segment_index] = jose.b64u_encode(bytes(raw))

    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(".".join(parts), RECIPIENT)


# --- the pieces underneath --------------------------------------------------


@given(st.binary(max_size=256))
def test_base64url_round_trips(data: bytes) -> None:
    assert jose.b64u_decode(jose.b64u_encode(data)) == data


@given(st.text(max_size=64))
def test_base64url_decodes_or_raises_value_error(data: str) -> None:
    with contextlib.suppress(ValueError):
        jose.b64u_decode(data)


@given(st.integers(min_value=0, max_value=2**4096))
def test_jwk_integers_round_trip(value: int) -> None:
    assert jose.uint_b64u(jose.b64u_uint(value)) == value


@given(
    st.binary(min_size=1, max_size=64),
    st.integers(min_value=1, max_value=96),
    st.binary(max_size=16),
    st.binary(max_size=16),
)
def test_concat_kdf_is_deterministic_and_the_length_asked_for(
    shared: bytes, length: int, apu: bytes, apv: bytes
) -> None:
    derived = jose.concat_kdf(shared, b"A256GCM", apu, apv, length)
    assert len(derived) == length
    assert derived == jose.concat_kdf(shared, b"A256GCM", apu, apv, length)
