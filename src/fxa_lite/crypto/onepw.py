"""The onepw protocol: password stretching, on both sides of the wire.

Client side (`fxa-auth-client/lib/{crypto,salt}.ts`) the password never leaves
the browser; what travels is `authPW`, and `unwrapBKey` stays behind to unwrap
`kB`.  Server side (`fxa-auth-server/lib/crypto/password.js`) `authPW` is
stretched again with scrypt and only the derived `verifyHash` is stored.

One detail decides whether any of this interoperates: scrypt's output is
converted to a **hex string** before it is used as HKDF input keying material,
and the Node `hkdf` package feeds that string to `Buffer.from()`.  So the IKM
is 64 ASCII bytes, not the 32 bytes they spell.  `StretchedPassword.stretched`
keeps the hex string for exactly that reason.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from .hkdf import NAMESPACE, derive

V1_MARKER = "quickStretch"
V2_MARKER = "quickStretchV2"
V1_ITERATIONS = 1000
V2_ITERATIONS = 650_000

#: scrypt parameters from `password.js` hash version 1.
SCRYPT_N = 65536
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
# Node picks `256 * N * r` when N or r exceeds its defaults; OpenSSL refuses the
# 64 MiB this needs unless we say so too.
SCRYPT_MAXMEM = 256 * SCRYPT_N * SCRYPT_R

_V1_RE = re.compile(f"^{re.escape(NAMESPACE + V1_MARKER)}:")
_V2_RE = re.compile(f"^{re.escape(NAMESPACE + V2_MARKER)}:")
_HEX32_RE = re.compile(r"^[a-f0-9]{32}$")


class SaltError(ValueError):
    """Raised for a salt string that does not parse."""


@dataclass(frozen=True, slots=True)
class Salt:
    """A parsed client key-stretching salt.

    v1's value is the email the account signed up with, v2's is a random
    32-character hex string that the server hands out, so that changing the
    email no longer invalidates the password.
    """

    version: int
    value: str

    def __str__(self) -> str:
        marker = V1_MARKER if self.version == 1 else V2_MARKER
        return f"{NAMESPACE}{marker}:{self.value}"

    @property
    def iterations(self) -> int:
        return V1_ITERATIONS if self.version == 1 else V2_ITERATIONS


def create_salt_v1(email: str) -> Salt:
    if "@" not in email.strip("@"):
        raise SaltError("salt value must be email like")
    return Salt(1, email)


def create_salt_v2(value: str | None = None) -> Salt:
    if value is None:
        value = secrets.token_hex(16)
    if not _HEX32_RE.match(value):
        raise SaltError("Invalid v2 salt value. Must be 32 character random hex string.")
    return Salt(2, value)


def parse_salt(salt: str) -> Salt:
    if _V2_RE.match(salt):
        return create_salt_v2(_V2_RE.sub("", salt))
    if _V1_RE.match(salt):
        return create_salt_v1(_V1_RE.sub("", salt))
    raise SaltError("invalid salt format")


@dataclass(frozen=True, slots=True)
class Credentials:
    """What the client derives from the password and sends/keeps."""

    #: Sent to the server in place of the password.
    auth_pw: bytes
    #: Never sent; XORed with `wrapKb` to recover `kB`.
    unwrap_b_key: bytes


def quick_stretch(password: str, salt: Salt) -> bytes:
    """PBKDF2-HMAC-SHA256 over the password, salted per `lib/salt.ts`."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), str(salt).encode(), salt.iterations, dklen=32
    )


def credentials(password: str, salt: Salt) -> Credentials:
    """`getCredentials` / `getCredentialsV2` — note the lowercase k in `unwrapBkey`."""
    stretched = quick_stretch(password, salt)
    return Credentials(
        auth_pw=derive(stretched, "authPW"),
        unwrap_b_key=derive(stretched, "unwrapBkey"),
    )


def credentials_v1(email: str, password: str) -> Credentials:
    return credentials(password, create_salt_v1(email))


def credentials_v2(password: str, client_salt: str | Salt) -> Credentials:
    salt = parse_salt(client_salt) if isinstance(client_salt, str) else client_salt
    if salt.version != 2:
        raise SaltError("Invalid v2 clientSalt")
    return credentials(password, salt)


@dataclass(frozen=True, slots=True)
class StretchedPassword:
    """The scrypt-stretched `authPW`, as a hex string.

    Hex, not bytes, because the reference server hands the hex string to a
    `Buffer.from()` that treats it as UTF-8. Everything derived from it inherits
    that encoding.
    """

    stretched: str

    @property
    def _ikm(self) -> bytes:
        return self.stretched.encode()

    @property
    def verify_hash(self) -> bytes:
        """What the accounts table stores; never enough to recover `authPW`."""
        return derive(self._ikm, "verifyHash")

    def matches(self, verify_hash: bytes) -> bool:
        return hmac.compare_digest(self.verify_hash, verify_hash)

    def wrap(self, payload: bytes, context: str = "wrapwrapKey") -> bytes:
        """XOR `payload` with the derived wrapper. Its own inverse, hence no `unwrap`."""
        return xor(derive(self._ikm, context), payload)


def stretch(auth_pw: bytes, auth_salt: bytes) -> StretchedPassword:
    """scrypt, `password.js` hash version 1. Deliberately slow: ~100 ms and 64 MiB."""
    stretched = hashlib.scrypt(
        auth_pw,
        salt=auth_salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_LENGTH,
        maxmem=SCRYPT_MAXMEM,
    )
    return StretchedPassword(stretched.hex())


def xor(a: bytes, b: bytes) -> bytes:
    """`butil.xorBuffers` — equal lengths only, so a truncation can't pass silently."""
    if len(a) != len(b):
        raise ValueError(f"XOR buffers must be same length ({len(a)} != {len(b)})")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))
