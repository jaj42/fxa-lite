# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Session, key-fetch and friends: one 32-byte seed, three derived keys.

`lib/tokens/token.js` expands the seed to 96 bytes and slices it into an `id`
(the lookup key, sent in the clear), an `authKey` (the HAWK MAC key) and a
`bundleKey` (used to encrypt payloads back to the client).  The seed itself is
returned to the client and never stored: the server keeps `id` and `authKey`,
so a database leak yields no way to sign a request... except that the reference
server no longer verifies HAWK MACs, which is why `id` alone authenticates.

`bundle` / `unbundle` are `lib/tokens/bundle.js`: HKDF out a MAC key and a
one-time pad the length of the payload, XOR, then HMAC the ciphertext.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from .hkdf import derive
from .onepw import xor

#: Length of the account/keys payload: kA || wrapKb.
ACCOUNT_KEYS_LENGTH = 64
MAC_LENGTH = 32


class TokenType(StrEnum):
    """`tokenTypeID` — part of the HKDF info string, so these strings are protocol."""

    SESSION = "sessionToken"
    KEY_FETCH = "keyFetchToken"
    ACCOUNT_RESET = "accountResetToken"
    PASSWORD_CHANGE = "passwordChangeToken"  # noqa: S105 - a token *type*, not a token
    PASSWORD_FORGOT = "passwordForgotToken"  # noqa: S105 - likewise


#: `Bearer <prefix>_<id>`, per `auth-schemes/bearer-fxa-token.js`. The
#: with-verification-status variant of keyFetchToken shares `fxk`: same wire id,
#: different server-side lookup.
BEARER_PREFIXES: dict[TokenType, str] = {
    TokenType.SESSION: "fxs",
    TokenType.KEY_FETCH: "fxk",
    TokenType.ACCOUNT_RESET: "fxar",
    TokenType.PASSWORD_CHANGE: "fxpc",
    TokenType.PASSWORD_FORGOT: "fxpf",
}


class BundleError(ValueError):
    """Raised when a bundle's MAC does not check out (errno 109, invalid signature)."""


@dataclass(frozen=True, slots=True)
class TokenKeys:
    """The three keys derived from a token's seed, plus the seed itself."""

    #: The 32-byte seed. Handed to the client as the token; not stored.
    data: bytes
    id: bytes
    #: HAWK MAC key. Stored, but unverified by both us and the reference server.
    auth_key: bytes
    bundle_key: bytes

    @property
    def token(self) -> str:
        return self.data.hex()

    def bearer_header(self, token_type: TokenType) -> str:
        return f"Bearer {BEARER_PREFIXES[token_type]}_{self.id.hex()}"


def derive_token_keys(token_type: TokenType, data: bytes) -> TokenKeys:
    """`Token.deriveTokenKeys`: 96 bytes of HKDF, sliced in three."""
    if len(data) != 32:
        raise ValueError(f"token seed must be 32 bytes, got {len(data)}")
    km = derive(data, token_type, length=3 * 32)
    return TokenKeys(data=data, id=km[0:32], auth_key=km[32:64], bundle_key=km[64:96])


def new_token(token_type: TokenType) -> TokenKeys:
    return derive_token_keys(token_type, secrets.token_bytes(32))


def bundle(bundle_key: bytes, key_info: str, payload: bytes) -> bytes:
    """XOR-encrypt `payload` under a one-time pad derived from `bundle_key`, then MAC."""
    hmac_key, xor_key = _bundle_keys(bundle_key, key_info, len(payload))
    ciphertext = xor(payload, xor_key)
    return ciphertext + hmac.new(hmac_key, ciphertext, sha256).digest()


def unbundle(bundle_key: bytes, key_info: str, payload: bytes) -> bytes:
    ciphertext, expected_mac = payload[:-MAC_LENGTH], payload[-MAC_LENGTH:]
    hmac_key, xor_key = _bundle_keys(bundle_key, key_info, len(ciphertext))
    mac = hmac.new(hmac_key, ciphertext, sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise BundleError("invalid signature")
    return xor(ciphertext, xor_key)


def bundle_account_keys(bundle_key: bytes, ka: bytes, wrap_kb: bytes) -> bytes:
    """The `GET /v1/account/keys` payload. Precomputed when the token is created."""
    return bundle(bundle_key, "account/keys", ka + wrap_kb)


def unbundle_account_keys(bundle_key: bytes, payload: bytes) -> tuple[bytes, bytes]:
    plaintext = unbundle(bundle_key, "account/keys", payload)
    if len(plaintext) != ACCOUNT_KEYS_LENGTH:
        raise BundleError(f"expected {ACCOUNT_KEYS_LENGTH} bytes of keys, got {len(plaintext)}")
    return plaintext[:32], plaintext[32:]


def _bundle_keys(bundle_key: bytes, key_info: str, payload_size: int) -> tuple[bytes, bytes]:
    km = derive(bundle_key, key_info, length=MAC_LENGTH + payload_size)
    return km[:MAC_LENGTH], km[MAC_LENGTH:]
