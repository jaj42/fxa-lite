# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Scoped key derivation, including the legacy Sync path."""

import pytest

from fxa_lite.crypto import scoped_keys
from fxa_lite.crypto.jose import b64u_decode
from vectors import load

VECTORS = load("scoped_keys")

NOTES = VECTORS["keys"][0]


def _derive(vector: dict) -> dict:
    return scoped_keys.derive_scoped_key(
        scope=vector["scope"],
        kb=bytes.fromhex(vector["kb"]),
        uid=vector["uid"],
        key_rotation_timestamp=vector["key_rotation_timestamp"],
        key_rotation_secret=bytes.fromhex(vector["key_rotation_secret"]),
    )


@pytest.mark.parametrize("vector", VECTORS["keys"], ids=lambda v: v["name"])
def test_scoped_key_matches_vector(vector) -> None:
    key = _derive(vector)
    assert key == {
        "kty": "oct",
        "scope": vector["scope"],
        "k": vector["k"],
        "kid": vector["kid"],
    }


def test_sync_keys_are_sixty_four_bytes_and_others_thirty_two() -> None:
    sync = _derive(VECTORS["keys"][2])
    assert len(b64u_decode(sync["k"])) == 64
    assert len(b64u_decode(NOTES["k"])) == 32


def test_thunderbird_shares_the_sync_key_but_not_the_kid() -> None:
    oldsync, thunderbird = _derive(VECTORS["keys"][2]), _derive(VECTORS["keys"][3])
    assert oldsync["k"] == thunderbird["k"]
    assert oldsync["kid"] != thunderbird["kid"]


def test_sync_kid_carries_millisecond_precision() -> None:
    # The general case rounds to seconds; Sync does not, because the tokenserver
    # matches the kid against `keysChangedAt` in milliseconds.
    vector = VECTORS["keys"][2]
    assert _derive(vector)["kid"].startswith(f"{vector['key_rotation_timestamp']}-")


def test_general_kid_rounds_the_timestamp_to_seconds() -> None:
    # 1494446722583 ms rounds up to 1494446723 s, matching JS `Math.round`.
    assert _derive(NOTES)["kid"].startswith("1494446723-")


def test_client_state_is_the_sync_kid_suffix() -> None:
    vector = VECTORS["keys"][2]
    kid_suffix = _derive(vector)["kid"].split("-", 1)[1]
    assert scoped_keys.client_state(bytes.fromhex(vector["kb"])) == b64u_decode(kid_suffix).hex()


def _derive_notes(
    *,
    scope: str = NOTES["scope"],
    kb: bytes = bytes.fromhex(NOTES["kb"]),
    uid: str = NOTES["uid"],
    key_rotation_timestamp: int = NOTES["key_rotation_timestamp"],
    key_rotation_secret: bytes = scoped_keys.NULL_KEY_ROTATION_SECRET,
) -> dict:
    return scoped_keys.derive_scoped_key(
        scope=scope,
        kb=kb,
        uid=uid,
        key_rotation_timestamp=key_rotation_timestamp,
        key_rotation_secret=key_rotation_secret,
    )


def test_scope_uid_and_kb_all_separate_key_material() -> None:
    derived = _derive_notes()["k"]
    assert _derive_notes(scope="https://example.com/other")["k"] != derived
    assert _derive_notes(uid="f" * 32)["k"] != derived
    assert _derive_notes(kb=bytes(32))["k"] != derived
    assert _derive_notes(key_rotation_secret=bytes(range(32)))["k"] != derived


def test_uid_does_not_affect_the_sync_key() -> None:
    # Legacy: the Sync key predates uid-salting, and changing that would lock
    # every existing account out of its own encrypted records.
    vector = VECTORS["keys"][2]
    assert _derive({**vector, "uid": "0" * 32})["k"] == vector["k"]


@pytest.mark.parametrize(
    "override",
    [
        {"kb": bytes(31)},
        {"key_rotation_secret": bytes(31)},
        {"uid": "not hex"},
        {"uid": NOTES["uid"][:16]},
        {"key_rotation_timestamp": 100},
        {"scope": "https://x"},
    ],
    ids=["short-kb", "short-secret", "non-hex-uid", "short-uid", "short-timestamp", "short-scope"],
)
def test_rejects_malformed_input(override) -> None:
    with pytest.raises(ValueError):
        _derive_notes(**override)
