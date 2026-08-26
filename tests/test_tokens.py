# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Token key derivation and the account/keys bundle."""

import pytest

from fxa_lite.crypto import tokens
from vectors import load

VECTORS = load("tokens")


@pytest.mark.parametrize("vector", VECTORS["derivations"], ids=lambda v: v["name"])
def test_derivation_matches_vector(vector) -> None:
    token_type = tokens.TokenType(vector["token_type"])
    keys = tokens.derive_token_keys(token_type, bytes.fromhex(vector["data"]))

    assert keys.token == vector["data"]
    assert keys.id.hex() == vector["id"]
    assert keys.auth_key.hex() == vector["auth_key"]
    if "bundle_key" in vector:
        assert keys.bundle_key.hex() == vector["bundle_key"]
    assert keys.bearer_header(token_type) == vector["bearer_header"]


@pytest.mark.parametrize("vector", VECTORS["account_keys_bundles"], ids=lambda v: v["name"])
def test_account_keys_bundle_matches_vector(vector) -> None:
    bundle_key = bytes.fromhex(vector["bundle_key"])
    ka = bytes.fromhex(vector["ka"])
    wrap_kb = bytes.fromhex(vector["wrap_kb"])

    assert tokens.bundle_account_keys(bundle_key, ka, wrap_kb).hex() == vector["bundle"]
    assert tokens.unbundle_account_keys(bundle_key, bytes.fromhex(vector["bundle"])) == (
        ka,
        wrap_kb,
    )


def test_every_token_type_has_a_bearer_prefix() -> None:
    assert set(tokens.BEARER_PREFIXES) == set(tokens.TokenType)


def test_bearer_prefixes_match_the_server_table() -> None:
    # `auth-schemes/bearer-fxa-token.js`; changing one of these is a wire break.
    assert {t.value: p for t, p in tokens.BEARER_PREFIXES.items()} == {
        "sessionToken": "fxs",
        "keyFetchToken": "fxk",
        "accountResetToken": "fxar",
        "passwordChangeToken": "fxpc",
        "passwordForgotToken": "fxpf",
    }


def test_token_types_derive_different_keys_from_the_same_seed() -> None:
    seed = bytes(range(32))
    ids = {tokens.derive_token_keys(t, seed).id for t in tokens.TokenType}
    assert len(ids) == len(tokens.TokenType)


def test_new_token_is_random_and_derived_from_its_own_seed() -> None:
    first = tokens.new_token(tokens.TokenType.SESSION)
    second = tokens.new_token(tokens.TokenType.SESSION)
    assert first.data != second.data
    assert tokens.derive_token_keys(tokens.TokenType.SESSION, first.data) == first


def test_seed_must_be_thirty_two_bytes() -> None:
    with pytest.raises(ValueError):
        tokens.derive_token_keys(tokens.TokenType.SESSION, bytes(16))


def test_bundle_round_trips_payloads_of_any_length() -> None:
    key = bytes(range(32))
    for payload in (b"", b"x", bytes(range(64)), bytes(200)):
        assert tokens.unbundle(key, "test", tokens.bundle(key, "test", payload)) == payload


def test_unbundle_rejects_a_bundle_from_another_token() -> None:
    payload = bytes(range(64))
    bundle = tokens.bundle(bytes(32), "account/keys", payload)
    with pytest.raises(tokens.BundleError):
        tokens.unbundle(bytes([1]) + bytes(31), "account/keys", bundle)


def test_unbundle_rejects_a_tampered_ciphertext() -> None:
    key = bytes(range(32))
    bundle = bytearray(tokens.bundle(key, "account/keys", bytes(64)))
    bundle[0] ^= 0xFF
    with pytest.raises(tokens.BundleError):
        tokens.unbundle(key, "account/keys", bytes(bundle))


def test_unbundle_rejects_a_different_key_info() -> None:
    key = bytes(range(32))
    with pytest.raises(tokens.BundleError):
        tokens.unbundle(key, "other/context", tokens.bundle(key, "account/keys", bytes(64)))


def test_unbundle_account_keys_rejects_a_wrong_length_payload() -> None:
    key = bytes(range(32))
    with pytest.raises(tokens.BundleError):
        tokens.unbundle_account_keys(key, tokens.bundle(key, "account/keys", bytes(32)))
