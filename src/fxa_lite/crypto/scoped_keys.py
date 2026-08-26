# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Per-scope keys derived from `kB`, as JWKs.

`libs/vendored/crypto-relier/src/lib/deriver/scoped-keys.ts`.  A relier that
asks for a scoped key gets 32 bytes bound to (scope, uid, key rotation), so no
two scopes — and no two accounts — share key material.

Sync predates all of that and gets a special case: 64 bytes derived from `kB`
alone, with a `kid` built from a hash of `kB`, which is what lets an existing
Sync account keep reading its own encrypted records.  Firefox and Thunderbird
both take that path.
"""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Any

from .hkdf import NAMESPACE, hkdf
from .jose import b64u_encode

KEY_LENGTH = 48

OLDSYNC_SCOPE = "https://identity.mozilla.com/apps/oldsync"
THUNDERBIRD_SYNC_SCOPE = "https://identity.thunderbird.net/apps/sync"
#: Scopes that use the legacy 64-byte Sync derivation.
SYNC_SCOPES = frozenset({OLDSYNC_SCOPE, THUNDERBIRD_SYNC_SCOPE})

#: We never rotate scoped keys, so the secret is a constant, as it is upstream.
NULL_KEY_ROTATION_SECRET = bytes(32)

_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def derive_scoped_key(
    *,
    scope: str,
    kb: bytes,
    uid: str,
    key_rotation_timestamp: int,
    key_rotation_secret: bytes = NULL_KEY_ROTATION_SECRET,
) -> dict[str, Any]:
    """Return the `oct` JWK for `scope`; `key_rotation_timestamp` is in milliseconds."""
    if len(kb) != 32:
        raise ValueError("inputKey must be 32 bytes")
    if len(key_rotation_secret) != 32:
        raise ValueError("keyRotationSecret must be 32 bytes")
    if not _HEX32_RE.match(uid):
        raise ValueError("uid must be a 32-character hex string")
    if len(str(key_rotation_timestamp)) != 13:
        raise ValueError("keyRotationTimestamp must be a 13-digit integer")
    if len(scope) < 10:
        raise ValueError("identifier must be a string of length >= 10")

    if scope in SYNC_SCOPES:
        return _legacy_sync_key(scope, kb, key_rotation_timestamp)

    info = f"{NAMESPACE}scoped_key\n{scope}".encode()
    km = hkdf(kb + key_rotation_secret, info, salt=bytes.fromhex(uid), length=KEY_LENGTH)
    # Math.round, on an integer number of milliseconds.
    seconds = (key_rotation_timestamp + 500) // 1000
    return {
        "kty": "oct",
        "scope": scope,
        "k": b64u_encode(km[16:48]),
        "kid": f"{seconds}-{b64u_encode(km[0:16])}",
    }


def _legacy_sync_key(scope: str, kb: bytes, key_rotation_timestamp: int) -> dict[str, Any]:
    """64 bytes of key, and a `kid` the Sync tokenserver can match on."""
    km = hkdf(kb, f"{NAMESPACE}oldsync".encode(), length=64)
    return {
        "kty": "oct",
        "scope": scope,
        "k": b64u_encode(km),
        # Full millisecond precision here, unlike the general case.
        "kid": f"{key_rotation_timestamp}-{b64u_encode(sha256(kb).digest()[:16])}",
    }


def client_state(kb: bytes) -> str:
    """The `X-Client-State` / `fxa_kid` half of the Sync `kid`: sha256(kB)[:16]."""
    return sha256(kb).digest()[:16].hex()
