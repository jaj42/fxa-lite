# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Client-side credential derivation, and the server-side stretch on top of it."""

import hashlib

import pytest

from fxa_lite.crypto import onepw
from vectors import load

VECTORS = load("onepw")


def _salt(vector: dict) -> onepw.Salt:
    if vector["version"] == 1:
        return onepw.create_salt_v1(vector["email"])
    return onepw.create_salt_v2(vector["client_salt"])


@pytest.mark.parametrize("vector", VECTORS["credentials"], ids=lambda v: v["name"])
def test_credentials_match_the_client_vectors(vector) -> None:
    credentials = onepw.credentials(vector["password"], _salt(vector))
    assert credentials.auth_pw.hex() == vector["auth_pw"]
    assert credentials.unwrap_b_key.hex() == vector["unwrap_b_key"]


def test_credentials_v1_helper_agrees_with_the_general_form() -> None:
    vector = VECTORS["credentials"][0]
    assert onepw.credentials_v1(vector["email"], vector["password"]).auth_pw.hex() == (
        vector["auth_pw"]
    )


def test_credentials_v2_helper_accepts_the_salt_string() -> None:
    vector = VECTORS["credentials"][1]
    salt = str(onepw.create_salt_v2(vector["client_salt"]))
    assert onepw.credentials_v2(vector["password"], salt).auth_pw.hex() == vector["auth_pw"]


def test_credentials_v2_rejects_a_v1_salt() -> None:
    with pytest.raises(onepw.SaltError):
        onepw.credentials_v2("pässwörd", onepw.create_salt_v1("a@b.c"))


def test_salt_strings_round_trip() -> None:
    v1 = onepw.create_salt_v1("foo@bar.com")
    assert str(v1) == "identity.mozilla.com/picl/v1/quickStretch:foo@bar.com"
    assert onepw.parse_salt(str(v1)) == v1

    v2 = onepw.create_salt_v2("0123456789abcdef0123456789abcdef")
    assert str(v2) == (
        "identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef0123456789abcdef"
    )
    assert onepw.parse_salt(str(v2)) == v2


def test_iterations_differ_by_version() -> None:
    assert onepw.create_salt_v1("a@b.c").iterations == 1000
    assert onepw.create_salt_v2().iterations == 650_000


@pytest.mark.parametrize(
    "salt",
    [
        "identity.mozilla.com/picl/v1/quickStretch:not-an-email",
        "identity.mozilla.com/picl/v1/quickStretchV2:tooshort",
        "identity.mozilla.com/picl/v1/quickStretchV2:0123456789ABCDEF0123456789ABCDEF",
        "foo/quickStretch:a@b.c",
        "identity.mozilla.com/picl/v1/bar:a@b.c",
    ],
)
def test_parse_salt_rejects_malformed(salt) -> None:
    with pytest.raises(onepw.SaltError):
        onepw.parse_salt(salt)


def test_generated_v2_salts_are_distinct_and_hex() -> None:
    first, second = onepw.create_salt_v2(), onepw.create_salt_v2()
    assert first != second
    assert len(first.value) == 32
    bytes.fromhex(first.value)


def test_scrypt_matches_the_server_vector() -> None:
    vector = VECTORS["scrypt"]
    stretched = onepw.stretch(
        bytes.fromhex(vector["auth_pw"]), vector["auth_salt_text"].encode()
    )
    assert stretched.stretched == vector["stretched"]


def test_verify_hash_keys_on_the_hex_string_not_the_bytes() -> None:
    # `password.js` hands scrypt's *hex output* to `Buffer.from()`, so the HKDF
    # input keying material is 64 ASCII bytes. Deriving from the 32 raw bytes
    # instead produces a plausible-looking hash that no real client can match.
    stretched = onepw.StretchedPassword("aa" * 32)
    from fxa_lite.crypto.hkdf import derive

    assert stretched.verify_hash == derive(b"aa" * 32, "verifyHash")
    assert stretched.verify_hash != derive(bytes.fromhex("aa" * 32), "verifyHash")


def test_verify_hash_matches_only_itself() -> None:
    stretched = onepw.stretch(bytes(32), b"salt")
    other = onepw.stretch(bytes(32), b"different salt")
    assert stretched.matches(stretched.verify_hash)
    assert not stretched.matches(other.verify_hash)


def test_wrap_is_its_own_inverse_and_hides_the_key() -> None:
    stretched = onepw.stretch(bytes(32), b"salt")
    wrap_kb = bytes(range(32))
    wrapped = stretched.wrap(wrap_kb)
    assert wrapped != wrap_kb
    assert stretched.wrap(wrapped) == wrap_kb


def test_wrap_context_separates_derivations() -> None:
    stretched = onepw.stretch(bytes(32), b"salt")
    payload = bytes(32)
    assert stretched.wrap(payload) != stretched.wrap(payload, context="otherContext")


def test_kb_survives_a_full_wrap_unwrap_round_trip() -> None:
    # The whole point of the protocol: the server stores wrapWrapKb and can only
    # give kB back to someone who knows the password.
    credentials = onepw.credentials_v1("user@example.com", "hunter2")
    kb = hashlib.sha256(b"the account's master key").digest()
    wrap_kb = onepw.xor(kb, credentials.unwrap_b_key)

    stretched = onepw.stretch(credentials.auth_pw, bytes(32))
    stored = stretched.wrap(wrap_kb)

    recovered = onepw.xor(stretched.wrap(stored), credentials.unwrap_b_key)
    assert recovered == kb


def test_xor_refuses_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        onepw.xor(bytes(2), bytes(4))
