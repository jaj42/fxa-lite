# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""tokenlib's wire format, pinned at the level a reader depends on.

There is no known-answer vector upstream — `token/native.rs`'s only test is a
round trip — so what is pinned here is the handful of encoding choices a
storage node's parser would trip over, each of which is a plausible mistake:

* the base64 is URL-safe **with** padding, unlike every other base64url in
  this codebase;
* the salt is three random bytes rendered as six hex characters, and it goes
  *inside* the signed payload as well as into the key derivation;
* the derive info ends with the token's own base64 text, so the key is bound
  to the exact bytes of the id and not merely to the claims.

The round trip itself is tested in `test_tokenserver.py`, against the reader in
`tests/conformance/client.py` rather than against this module.
"""

import base64
import hashlib
import hmac
import json

import pytest

from fxa_lite.crypto import jose
from fxa_lite.tokenserver import tokenlib

SECRET = "a shared secret, agreed out of band"
CLAIMS = {"node": "https://storage.example", "fxa_uid": "abc", "uid": 7, "expires": 1031}


def test_token_is_padded_url_safe_base64() -> None:
    """`URL_SAFE`, not `URL_SAFE_NO_PAD` — a strict decoder must accept it as-is."""
    token, _ = tokenlib.make_token(CLAIMS, SECRET)
    assert set(token) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    )
    # No padding added, none stripped: this must decode without adjustment.
    assert base64.urlsafe_b64decode(token)


def test_payload_is_the_claims_plus_a_six_character_hex_salt() -> None:
    token, _ = tokenlib.make_token(CLAIMS, SECRET)
    raw = base64.urlsafe_b64decode(token)
    payload = json.loads(raw[: -tokenlib.MAC_LENGTH])
    assert {key: payload[key] for key in CLAIMS} == CLAIMS
    assert len(payload["salt"]) == 6
    bytes.fromhex(payload["salt"])


def test_signature_is_hmac_over_the_payload_bytes() -> None:
    """Over the JSON, not over the base64 — the id carries both concatenated."""
    token, _ = tokenlib.make_token(CLAIMS, SECRET)
    raw = base64.urlsafe_b64decode(token)
    payload, mac = raw[: -tokenlib.MAC_LENGTH], raw[-tokenlib.MAC_LENGTH :]
    key = tokenlib.signing_key(SECRET)
    assert hmac.compare_digest(mac, hmac.new(key, payload, hashlib.sha256).digest())


def test_key_is_bound_to_the_token_text() -> None:
    """Changing one character of the id must change the key it implies."""
    token, key = tokenlib.make_token(CLAIMS, SECRET)
    salt = json.loads(base64.urlsafe_b64decode(token)[: -tokenlib.MAC_LENGTH])["salt"]
    assert tokenlib.derive_secret(token, salt, SECRET) == key
    tampered = ("A" if token[0] != "A" else "B") + token[1:]
    assert tokenlib.derive_secret(tampered, salt, SECRET) != key


def test_key_is_32_bytes_of_padded_base64() -> None:
    _, key = tokenlib.make_token(CLAIMS, SECRET)
    assert len(base64.urlsafe_b64decode(key)) == 32


def test_a_different_secret_yields_a_different_signing_key() -> None:
    assert tokenlib.signing_key(SECRET) != tokenlib.signing_key(SECRET + "!")


# --------------------------------------------------------------------------
# The shared secret, and the metrics hashes.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def private_key():
    return jose.generate_signing_key()


def test_a_configured_secret_is_used_verbatim(private_key) -> None:
    assert tokenlib.resolve_shared_secret("literally this", private_key) == "literally this"


def test_a_derived_secret_is_stable_and_key_specific(private_key) -> None:
    """Restarting must not invalidate outstanding tokens; rotating the key may."""
    derived = tokenlib.resolve_shared_secret(None, private_key)
    assert derived == tokenlib.resolve_shared_secret(None, private_key)
    assert derived != tokenlib.resolve_shared_secret(None, jose.generate_signing_key())
    assert derived


def test_an_empty_configured_secret_falls_back_to_deriving_one(private_key) -> None:
    """`tokenserver_shared_secret = ""` is a typo, not a request for no secret."""
    assert tokenlib.resolve_shared_secret("", private_key) == tokenlib.resolve_shared_secret(
        None, private_key
    )


def test_metrics_hash_is_a_truncated_keyed_digest() -> None:
    digest = tokenlib.metrics_hash("some-uid", SECRET)
    assert len(digest) == 32
    assert digest == hmac.new(SECRET.encode(), b"some-uid", hashlib.sha256).hexdigest()[:32]
    assert digest != tokenlib.metrics_hash("some-uid", SECRET + "!")


def test_hashed_device_id_hashes_the_already_hashed_uid() -> None:
    """Upstream's parameter is named `fxa_uid` but is passed the hashed one."""
    hashed_uid = tokenlib.metrics_hash("some-uid", SECRET)
    assert tokenlib.hashed_device_id(hashed_uid, SECRET) == tokenlib.metrics_hash(
        hashed_uid + "none", SECRET
    )
