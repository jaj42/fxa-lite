"""Compact JWE: the `keys_jwe` bundle (ECDH-ES) and the pre-shared-key form."""

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


def test_dir_round_trips() -> None:
    cek = bytes(range(32))
    jwe = jose.encrypt_jwe_dir(cek, b'{"kB":"aaaa"}', kid="recovery-key-id")
    header = json.loads(jose.b64u_decode(jwe.split(".")[0]))
    assert header == {"enc": "A256GCM", "alg": "dir", "kid": "recovery-key-id"}
    assert jose.decrypt_jwe(jwe, cek) == b'{"kB":"aaaa"}'


def test_dir_rejects_the_wrong_key_length() -> None:
    with pytest.raises(jose.JWEError, match="32-byte key"):
        jose.encrypt_jwe_dir(bytes(16), b"data")


def test_decrypt_requires_the_matching_key_kind(recipient) -> None:
    ecdh = jose.encrypt_jwe_ecdh_es(jose.ec_public_key_to_jwk(recipient.public_key()), b"d")
    with pytest.raises(jose.JWEError, match="EC private key"):
        jose.decrypt_jwe(ecdh, bytes(32))

    with pytest.raises(jose.JWEError, match="content encryption key"):
        jose.decrypt_jwe(jose.encrypt_jwe_dir(bytes(32), b"d"), recipient)


@pytest.mark.parametrize(
    "jwe",
    [
        "a.b.c.d",
        "a.b.c.d.e.f",
        jose.b64u_encode(b'{"alg":"RSA-OAEP","enc":"A256GCM"}') + "..a.b.c",
        jose.b64u_encode(b'{"alg":"dir","enc":"A128GCM"}') + "..a.b.c",
        "not-base64url..a.b.c",
    ],
    ids=["too-few-segments", "too-many-segments", "unsupported-alg", "unsupported-enc", "garbage"],
)
def test_decrypt_rejects_malformed_or_unsupported(jwe) -> None:
    with pytest.raises(jose.JWEError):
        jose.decrypt_jwe(jwe, bytes(32))


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
