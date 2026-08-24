"""Compact JWE: the `keys_jwe` bundle, and every way a hostile one can be malformed."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from fxa_lite.crypto import jose, scoped_keys
from vectors import load

VECTORS = load("jose")
ECDH = VECTORS["ecdh_es"]
GCM = VECTORS["a256gcm"]


def _private_key(jwk: dict) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(
        int.from_bytes(jose.b64u_decode(jwk["d"]), "big"), ec.SECP256R1()
    )


@pytest.fixture
def recipient() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_ecdh_agreement_matches_rfc7518_appendix_c() -> None:
    sender = _private_key(ECDH["sender_private_jwk"])
    shared = sender.exchange(ec.ECDH(), jose.jwk_to_ec_public_key(ECDH["recipient_public_jwk"]))
    assert shared.hex() == ECDH["shared_secret"]

    derived = jose.concat_kdf(
        shared,
        ECDH["algorithm_id"].encode(),
        ECDH["apu"].encode(),
        ECDH["apv"].encode(),
        ECDH["key_length"],
    )
    assert jose.b64u_encode(derived) == ECDH["derived_key"]


def test_concat_kdf_binds_the_output_length() -> None:
    # SuppPubInfo carries keydatalen, so a shorter derivation is not a prefix of
    # a longer one. Getting this wrong silently produces the wrong CEK.
    shared = bytes.fromhex(ECDH["shared_secret"])
    short = jose.concat_kdf(shared, b"A128GCM", length=16)
    assert short != jose.concat_kdf(shared, b"A128GCM", length=32)[:16]


def test_content_encryption_matches_rfc7516_appendix_a1(monkeypatch) -> None:
    # Pins the framing our public API depends on: AAD is the ASCII base64url
    # protected header, the IV is 12 bytes, and the 16-byte tag is its own segment.
    monkeypatch.setattr(jose.os, "urandom", lambda n: bytes.fromhex(GCM["iv"]))
    jwe = jose._seal(
        GCM["protected_header"], bytes.fromhex(GCM["cek"]), GCM["plaintext"].encode()
    )
    protected, encrypted_key, iv, ciphertext, tag = jwe.split(".")
    assert protected == GCM["protected_b64u"]
    assert encrypted_key == ""
    assert iv == jose.b64u_encode(bytes.fromhex(GCM["iv"]))
    assert ciphertext == GCM["ciphertext"]
    assert tag == GCM["tag"]


def test_ecdh_es_round_trips(recipient) -> None:
    public_jwk = jose.ec_public_key_to_jwk(recipient.public_key())
    jwe = jose.encrypt_jwe_ecdh_es(public_jwk, b'{"kB":"aaaa"}')
    assert jose.decrypt_jwe(jwe, recipient) == b'{"kB":"aaaa"}'


def test_ecdh_es_header_is_a_direct_agreement(recipient) -> None:
    jwe = jose.encrypt_jwe_ecdh_es(jose.ec_public_key_to_jwk(recipient.public_key()), b"data")
    protected, encrypted_key, _, _, _ = jwe.split(".")
    header = json.loads(jose.b64u_decode(protected))

    assert header["alg"] == "ECDH-ES"
    assert header["enc"] == "A256GCM"
    assert header["epk"]["kty"] == "EC" and header["epk"]["crv"] == "P-256"
    assert "d" not in header["epk"]
    # Direct agreement: no wrapped key travels, so the segment is empty.
    assert encrypted_key == ""


def test_each_encryption_uses_a_fresh_ephemeral_key(recipient) -> None:
    public_jwk = jose.ec_public_key_to_jwk(recipient.public_key())
    epks = {
        json.loads(jose.b64u_decode(jose.encrypt_jwe_ecdh_es(public_jwk, b"x").split(".")[0]))[
            "epk"
        ]["x"]
        for _ in range(3)
    }
    assert len(epks) == 3


def test_recipient_kid_is_echoed_back(recipient) -> None:
    public_jwk = jose.ec_public_key_to_jwk(recipient.public_key()) | {"kid": "client-key-1"}
    jwe = jose.encrypt_jwe_ecdh_es(public_jwk, b"data")
    header = json.loads(jose.b64u_decode(jwe.split(".")[0]))
    assert header["kid"] == "client-key-1"


def test_agreement_party_info_round_trips(recipient) -> None:
    jwe = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(recipient.public_key()), b"data", apu=b"Alice", apv=b"Bob"
    )
    header = json.loads(jose.b64u_decode(jwe.split(".")[0]))
    assert jose.b64u_decode(header["apu"]) == b"Alice"
    assert jose.b64u_decode(header["apv"]) == b"Bob"
    assert jose.decrypt_jwe(jwe, recipient) == b"data"


def test_another_recipient_cannot_decrypt(recipient) -> None:
    jwe = jose.encrypt_jwe_ecdh_es(jose.ec_public_key_to_jwk(recipient.public_key()), b"data")
    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(jwe, ec.generate_private_key(ec.SECP256R1()))


def test_tampering_with_the_header_breaks_decryption(recipient) -> None:
    # The protected header is the AEAD's additional data, so swapping in another
    # ephemeral key fails loudly instead of silently decrypting to garbage.
    jwe = jose.encrypt_jwe_ecdh_es(jose.ec_public_key_to_jwk(recipient.public_key()), b"data")
    protected, _, iv, ciphertext, tag = jwe.split(".")
    header = json.loads(jose.b64u_decode(protected))
    header["kid"] = "someone else"
    forged = jose.b64u_encode(json.dumps(header).encode())
    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(f"{forged}..{iv}.{ciphertext}.{tag}", recipient)


def test_tampering_with_the_ciphertext_breaks_decryption(recipient) -> None:
    protected, _, iv, ciphertext, tag = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(recipient.public_key()), b"data"
    ).split(".")
    flipped = bytearray(jose.b64u_decode(ciphertext))
    flipped[0] ^= 0xFF
    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(
            f"{protected}..{iv}.{jose.b64u_encode(bytes(flipped))}.{tag}", recipient
        )


@pytest.mark.parametrize(
    ("jwk", "message"),
    [
        ({"kty": "oct", "k": "U4ObmO4YmLfHLqYgFd9Q2Q"}, "not an EC key"),
        ({"kty": "RSA", "e": "AQAB", "n": "nV-WzW3lHd03yEUG88M"}, "not an EC key"),
        (
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "Txvn927uYdiqgSRtHgX3aTVH1_3bMyDM08yN-SRF7Q-2wouLoI70vawCO8i2UaAv",
                "y": "38oIUqk9a6qtAyq25PAvxwApdPcHg6RaXN3Du70E3sIHKbGtXBX0KBbcFh4yYKUu",
            },
            "not on curve P-256",
        ),
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "d": "KXAjjEr4KT9UlYI4BE0BefVdoxP8vqO389U7lQlCigs",
                "x": "SiBn6uebjigmQqw4TpNzs3AUyCae1_sG2b9Fzhq3Fyo",
                "y": "q99Xq1RWNTFpk99pdQOSjUvwELss51PkmAGCXhLfMV4",
            },
            "includes the private key",
        ),
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "SiBn6uebjigmQqw4TpNzs3AUyCae1_sG2b9Fzhq3Fyo",
                "y": "q99Xq1RWNTFpk99pdQOSjUvwELss51PkmAGCXhLfMV3",
            },
            "invalid EC public key",
        ),
    ],
    ids=["symmetric", "rsa", "wrong-curve", "private-key", "off-curve"],
)
def test_rejects_unusable_recipient_keys(jwk, message) -> None:
    # Same checks, same wording as `deriver-utils.ts`: a relier that generates
    # its key wrongly should hear about it now, not after shipping.
    with pytest.raises(jose.JWEError, match=message):
        jose.encrypt_jwe_ecdh_es(jwk, b"data")


@pytest.mark.parametrize(
    "jwe",
    [
        "",
        "a.b.c.d",
        "a.b.c.d.e.f",
        jose.b64u_encode(b'{"alg":"RSA-OAEP","enc":"A256GCM"}') + "..a.b.c",
        jose.b64u_encode(b'{"alg":"dir","enc":"A256GCM"}') + "..a.b.c",
        jose.b64u_encode(b'{"alg":"ECDH-ES","enc":"A128GCM"}') + "..a.b.c",
        jose.b64u_encode(b'{"alg":"none","enc":"A256GCM"}') + "..a.b.c",
        jose.b64u_encode(b"[]") + "..a.b.c",
        jose.b64u_encode(b"not json") + "..a.b.c",
        "not+base64url..a.b.c",
    ],
    ids=[
        "empty",
        "too-few-segments",
        "too-many-segments",
        "unsupported-alg",
        "alg-dir",
        "unsupported-enc",
        "alg-none",
        "header-not-an-object",
        "header-not-json",
        "header-not-base64url",
    ],
)
def test_decrypt_rejects_malformed_or_unsupported(jwe, recipient) -> None:
    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(jwe, recipient)


# --------------------------------------------------------------------------
# Hostile input. `decrypt_jwe` is not on the wire — `crypto.js` is, and this
# is the oracle it is checked against, so it gets the same adversarial pass.
# --------------------------------------------------------------------------


def _rebuilt(jwe: str, recipient=None, **header_changes) -> str:
    """The same JWE with its protected header edited — i.e. with the AAD broken."""
    protected, encrypted_key, iv, ciphertext, tag = jwe.split(".")
    header = json.loads(jose.b64u_decode(protected))
    for name, value in header_changes.items():
        if value is _REMOVE:
            header.pop(name, None)
        else:
            header[name] = value
    edited = jose.b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{edited}.{encrypted_key}.{iv}.{ciphertext}.{tag}"


_REMOVE = object()


@pytest.fixture
def sealed(recipient) -> str:
    return jose.encrypt_jwe_ecdh_es(jose.ec_public_key_to_jwk(recipient.public_key()), b"data")


def test_rejects_an_ephemeral_key_on_the_wrong_curve(sealed, recipient) -> None:
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_numbers()
    size = 48
    forged = _rebuilt(
        sealed,
        epk={
            "kty": "EC",
            "crv": "P-384",
            "x": jose.b64u_encode(p384.x.to_bytes(size, "big")),
            "y": jose.b64u_encode(p384.y.to_bytes(size, "big")),
        },
    )
    with pytest.raises(jose.JWEError, match="not on curve P-256"):
        jose.decrypt_jwe(forged, recipient)


def test_rejects_an_ephemeral_key_that_is_not_on_the_curve(sealed, recipient) -> None:
    """The invalid-curve attack.

    A point off P-256 lies on some other curve, often one with small subgroups;
    an implementation that multiplies its private scalar by it leaks that scalar
    a few bits at a time. `cryptography` runs the curve equation in
    `public_key()`, so this dies before any scalar multiplication — assert it,
    because the whole defence is that one call.
    """
    valid = json.loads(jose.b64u_decode(sealed.split(".")[0]))["epk"]
    y = bytearray(jose.b64u_decode(valid["y"]))
    y[-1] ^= 0x01
    forged = _rebuilt(sealed, epk=valid | {"y": jose.b64u_encode(bytes(y))})
    with pytest.raises(jose.JWEError, match="invalid EC public key"):
        jose.decrypt_jwe(forged, recipient)


def test_rejects_a_missing_ephemeral_key(sealed, recipient) -> None:
    with pytest.raises(jose.JWEError, match="no ephemeral public key"):
        jose.decrypt_jwe(_rebuilt(sealed, epk=_REMOVE), recipient)


@pytest.mark.parametrize("epk", ["", 42, [], None], ids=["string", "number", "array", "null"])
def test_rejects_an_ephemeral_key_that_is_not_an_object(sealed, recipient, epk) -> None:
    with pytest.raises(jose.JWEError, match="no ephemeral public key"):
        jose.decrypt_jwe(_rebuilt(sealed, epk=epk), recipient)


def test_rejects_compression(sealed, recipient) -> None:
    # We do not inflate anything, and a `zip` we ignore rather than refuse means
    # handing the caller DEFLATE bytes as if they were the plaintext.
    with pytest.raises(jose.JWEError, match="compression"):
        jose.decrypt_jwe(_rebuilt(sealed, zip="DEF"), recipient)


def test_rejects_critical_header_parameters(sealed, recipient) -> None:
    # RFC 7516 §4.1.13: `crit` means "reject this unless you implement it".
    with pytest.raises(jose.JWEError, match="critical header"):
        jose.decrypt_jwe(_rebuilt(sealed, crit=["exp"], exp=1), recipient)


def test_rejects_an_encrypted_key_segment(sealed, recipient) -> None:
    protected, _, iv, ciphertext, tag = sealed.split(".")
    with pytest.raises(jose.JWEError, match="no encrypted key"):
        jose.decrypt_jwe(f"{protected}.{jose.b64u_encode(b'x' * 32)}.{iv}.{ciphertext}.{tag}",
                         recipient)


@pytest.mark.parametrize("name", ["apu", "apv"])
def test_rejects_party_info_that_is_not_a_string(sealed, recipient, name) -> None:
    with pytest.raises(jose.JWEError, match=f"{name} is not a string"):
        jose.decrypt_jwe(_rebuilt(sealed, **{name: 42}), recipient)


def test_rejects_a_tampered_tag(sealed, recipient) -> None:
    protected, _, iv, ciphertext, tag = sealed.split(".")
    flipped = bytearray(jose.b64u_decode(tag))
    flipped[0] ^= 0xFF
    with pytest.raises(jose.JWEError, match="authentication failed"):
        jose.decrypt_jwe(
            f"{protected}..{iv}.{ciphertext}.{jose.b64u_encode(bytes(flipped))}", recipient
        )


@pytest.mark.parametrize(
    ("segment", "raw", "message"),
    [
        (2, bytes(11), "IV is 11 bytes"),
        (2, bytes(13), "IV is 13 bytes"),
        (4, bytes(15), "tag is 15 bytes"),
        (4, bytes(17), "tag is 17 bytes"),
    ],
    ids=["short-iv", "long-iv", "short-tag", "long-tag"],
)
def test_rejects_a_wrongly_sized_iv_or_tag(sealed, recipient, segment, raw, message) -> None:
    # AESGCM would take a 13-byte nonce and fail as an authentication error,
    # which reads as "wrong key" when what happened is "malformed".
    parts = sealed.split(".")
    parts[segment] = jose.b64u_encode(raw)
    with pytest.raises(jose.JWEError, match=message):
        jose.decrypt_jwe(".".join(parts), recipient)


@pytest.mark.parametrize("segment", [2, 3, 4], ids=["iv", "ciphertext", "tag"])
def test_rejects_a_segment_that_is_not_base64url(sealed, recipient, segment) -> None:
    parts = sealed.split(".")
    parts[segment] = "not+base64url"
    with pytest.raises(jose.JWEError, match="not base64url"):
        jose.decrypt_jwe(".".join(parts), recipient)


def test_rejects_an_oversized_body(recipient) -> None:
    body = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(recipient.public_key()), b"x" * jose.MAX_JWE_LENGTH
    )
    assert len(body) > jose.MAX_JWE_LENGTH
    with pytest.raises(jose.JWEError, match="longer than"):
        jose.decrypt_jwe(body, recipient)


def test_rejects_an_oversized_protected_header(sealed, recipient) -> None:
    forged = _rebuilt(sealed, pad="A" * jose.MAX_JWE_HEADER_LENGTH)
    with pytest.raises(jose.JWEError, match="header is longer than"):
        jose.decrypt_jwe(forged, recipient)


def test_a_real_keys_jwe_fits_well_inside_both_caps(recipient) -> None:
    # The caps have to sit above what the browser actually sends, or they are an
    # outage rather than a bound. `oauth/models.py` caps `keys_jwe` at 8 KiB too.
    kb = bytes(range(32))
    keys = {
        scoped_keys.OLDSYNC_SCOPE: scoped_keys.derive_scoped_key(
            scope=scoped_keys.OLDSYNC_SCOPE,
            kb=kb,
            uid="a" * 32,
            key_rotation_timestamp=1510726317123,
        )
    }
    blob = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(recipient.public_key()), json.dumps(keys).encode()
    )
    assert len(blob) < 1024
    assert len(blob.split(".")[0]) < jose.MAX_JWE_HEADER_LENGTH


def test_a_scoped_key_bundle_survives_the_round_trip(recipient) -> None:
    # What phase 3 actually ships: the scoped keys for a relier, encrypted to the
    # `keys_jwk` it sent, recovered by the client and matched against a direct
    # derivation from kB.
    kb = bytes.fromhex("eaf9570b7219a4187d3d6bf3cec2770c2e0719b7cc0dfbb38243d6f1881675e9")
    uid = "aeaa1725c7a24ff983c6295725d5fc9b"
    scope = scoped_keys.OLDSYNC_SCOPE
    key = scoped_keys.derive_scoped_key(
        scope=scope, kb=kb, uid=uid, key_rotation_timestamp=1510726317123
    )

    jwe = jose.encrypt_jwe_ecdh_es(
        jose.ec_public_key_to_jwk(recipient.public_key()), json.dumps({scope: key}).encode()
    )
    recovered = json.loads(jose.decrypt_jwe(jwe, recipient))
    assert recovered == {scope: key}
    assert len(jose.b64u_decode(recovered[scope]["k"])) == 64
