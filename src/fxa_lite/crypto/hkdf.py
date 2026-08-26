# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""RFC 5869 HKDF-SHA256, and the FxA key-derivation namespace.

Every HKDF in the FxA protocol is SHA-256 with an *empty* salt — RFC 5869 says
that degrades to `hashLen` zero bytes, which is exactly what the Node `hkdf`
package the reference server uses does with a null salt.  `derive()` is the
namespaced form the protocol actually speaks: `hkdf.js`'s `KW(info)` prefixes
every info string with `identity.mozilla.com/picl/v1/`.
"""

from __future__ import annotations

import hashlib
import hmac

#: Prefix on every FxA info string and password salt.
NAMESPACE = "identity.mozilla.com/picl/v1/"

HASH_LENGTH = hashlib.sha256().digest_size


def hkdf(ikm: bytes, info: bytes, salt: bytes = b"", length: int = 32) -> bytes:
    """RFC 5869 extract-then-expand with SHA-256."""
    if length > 255 * HASH_LENGTH:
        raise ValueError(f"cannot derive {length} bytes from HKDF-SHA256")
    prk = hmac.new(salt or bytes(HASH_LENGTH), ikm, hashlib.sha256).digest()
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def kw(name: str) -> bytes:
    """`identity.mozilla.com/picl/v1/<name>` — an HKDF info string."""
    return (NAMESPACE + name).encode()


def kwe(name: str, email: str) -> bytes:
    """`identity.mozilla.com/picl/v1/<name>:<email>` — a PBKDF2 salt."""
    return f"{NAMESPACE}{name}:{email}".encode()


def derive(ikm: bytes, name: str, salt: bytes = b"", length: int = 32) -> bytes:
    """HKDF with the info string namespaced, as `lib/crypto/hkdf.js` does it."""
    return hkdf(ikm, kw(name), salt, length)
