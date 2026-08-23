"""JOSE bits: base64url, JWK conversion, RS256 JWTs and compact JWE.

Three things live here, and all three are small enough that implementing them
beats taking on `pyjwt` + `jwcrypto`:

* **JWK conversion and signing-key generation**, for `/v1/jwks`.
* **RS256 JWTs**, the format of OAuth access tokens (`lib/oauth/jwt_access_token.js`).
* **Compact JWE**, two flavours. `ECDH-ES` + `A256GCM` to an ephemerally-agreed
  key is how scoped keys reach the relier (`deriver-utils.ts` — we are the
  encrypting side and never see the private half); `dir` + `A256GCM` is what
  `fxa-auth-client`'s `jweDecrypt` speaks.

Key generation mirrors `packages/fxa-auth-server/lib/oauth/keys.ts`
(`generatePrivateKey`): RSA-2048, `alg: RS256`, `use: sig`, a `kid` of
``YYYYMMDD-<sha256(pkcs1 public pem)[:8]>`` and an `fxa-createdAt` timestamp
rounded down to the hour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MODULUS_BITS = 2048
PUBLIC_EXPONENT = 65537

#: The only JWS algorithm anything in FxA signs or verifies.
ALGORITHM = "RS256"
#: Content encryption for both JWE flavours; 32-byte key, 12-byte IV, 16-byte tag.
CONTENT_ENCRYPTION = "A256GCM"
IV_LENGTH = 12
TAG_LENGTH = 16
CEK_LENGTH = 32

# The private JWK members, in the order pem2jwk emits them.
_PRIVATE_MEMBERS = ("n", "e", "d", "p", "q", "dp", "dq", "qi")


def b64u_encode(data: bytes) -> str:
    """base64url, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    """base64url, tolerating missing padding."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64u_uint(value: int) -> str:
    """Encode a JWK integer: minimal-length big-endian, then base64url."""
    length = max(1, (value.bit_length() + 7) // 8)
    return b64u_encode(value.to_bytes(length, "big"))


def uint_b64u(value: str) -> int:
    return int.from_bytes(b64u_decode(value), "big")


def generate_signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=MODULUS_BITS)


def key_id(public_key: rsa.RSAPublicKey, now: datetime | None = None) -> str:
    """`YYYYMMDD-<sha256(pkcs1 public pem)[:8]>`, as the reference server does it."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    fingerprint = hashlib.sha256(pem).hexdigest()[:8]
    now = now or datetime.now(UTC)
    return f"{now.strftime('%Y%m%d')}-{fingerprint}"


def private_key_to_jwk(
    key: rsa.RSAPrivateKey,
    *,
    kid: str | None = None,
    created_at: int | None = None,
) -> dict[str, Any]:
    """Serialize an RSA private key as an FxA-flavoured private JWK."""
    numbers = key.private_numbers()
    public = numbers.public_numbers
    if created_at is None:
        created_at = int(time.time() // 3600) * 3600
    return {
        "kty": "RSA",
        "kid": kid or key_id(key.public_key()),
        "alg": "RS256",
        "use": "sig",
        "fxa-createdAt": created_at,
        "n": b64u_uint(public.n),
        "e": b64u_uint(public.e),
        "d": b64u_uint(numbers.d),
        "p": b64u_uint(numbers.p),
        "q": b64u_uint(numbers.q),
        "dp": b64u_uint(numbers.dmp1),
        "dq": b64u_uint(numbers.dmq1),
        "qi": b64u_uint(numbers.iqmp),
    }


def public_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    """Strip a JWK down to its public members — this is what `/v1/jwks` serves.

    Mirrors `extractPublicKey`: be careful refactoring, it is the only thing
    standing between the signing key and the public internet.
    """
    public = {
        "kty": jwk["kty"],
        "alg": jwk.get("alg", "RS256"),
        "kid": jwk["kid"],
        "use": jwk.get("use", "sig"),
        "n": jwk["n"],
        "e": jwk["e"],
    }
    if "fxa-createdAt" in jwk:
        public["fxa-createdAt"] = jwk["fxa-createdAt"]
    return public


def jwk_to_private_key(jwk: dict[str, Any]) -> rsa.RSAPrivateKey:
    if jwk.get("kty") != "RSA":
        raise ValueError(f"unsupported key type: {jwk.get('kty')!r}")
    missing = [m for m in _PRIVATE_MEMBERS if m not in jwk]
    if missing:
        raise ValueError(f"private JWK is missing {', '.join(missing)}")
    public = rsa.RSAPublicNumbers(e=uint_b64u(jwk["e"]), n=uint_b64u(jwk["n"]))
    return rsa.RSAPrivateNumbers(
        p=uint_b64u(jwk["p"]),
        q=uint_b64u(jwk["q"]),
        d=uint_b64u(jwk["d"]),
        dmp1=uint_b64u(jwk["dp"]),
        dmq1=uint_b64u(jwk["dq"]),
        iqmp=uint_b64u(jwk["qi"]),
        public_numbers=public,
    ).private_key()


def jwk_to_public_key(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise ValueError(f"unsupported key type: {jwk.get('kty')!r}")
    return rsa.RSAPublicNumbers(e=uint_b64u(jwk["e"]), n=uint_b64u(jwk["n"])).public_key()


# --------------------------------------------------------------------------
# JWS: RS256, the format of an OAuth access token.
# --------------------------------------------------------------------------


class JWTError(ValueError):
    """Raised for a JWT that is malformed, wrongly signed, or expired."""


def sign_jwt(
    claims: Mapping[str, Any],
    key: rsa.RSAPrivateKey,
    *,
    kid: str,
    typ: str = "JWT",
) -> str:
    """Sign `claims` as a compact RS256 JWT.

    Access tokens use `typ="at+JWT"` (RFC 9068), which is what tells a resource
    server it is looking at an access token and not an ID token.
    """
    header = {"alg": ALGORITHM, "typ": typ, "kid": kid}
    signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{b64u_encode(signature)}"


def decode_jwt_header(token: str) -> dict[str, Any]:
    """Read the header without verifying anything — only safe for picking a key."""
    try:
        header = json.loads(b64u_decode(token.split(".", 1)[0]))
    except (ValueError, IndexError) as exc:
        raise JWTError("malformed JWT header") from exc
    if not isinstance(header, dict):
        raise JWTError("JWT header is not an object")
    return header


def verify_jwt(
    token: str,
    keys: Mapping[str, rsa.RSAPublicKey] | rsa.RSAPublicKey,
    *,
    now: int | None = None,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify signature and expiry, and return the claims.

    Audience, issuer and scope are the caller's business — they differ per route
    and getting them wrong should be a visible decision, not a default.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError(f"expected 3 JWT segments, got {len(parts)}")
    header = decode_jwt_header(token)
    if header.get("alg") != ALGORITHM:
        raise JWTError(f"unsupported JWT algorithm: {header.get('alg')!r}")

    if isinstance(keys, Mapping):
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in keys:
            raise JWTError(f"no signing key for kid {kid!r}")
        key = keys[kid]
    else:
        key = keys

    try:
        key.verify(
            b64u_decode(parts[2]),
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise JWTError("bad JWT signature") from exc

    try:
        claims = json.loads(b64u_decode(parts[1]))
    except ValueError as exc:
        raise JWTError("malformed JWT payload") from exc
    if not isinstance(claims, dict):
        raise JWTError("JWT payload is not an object")

    expires = claims.get("exp")
    if isinstance(expires, int | float):
        if now is None:
            now = int(time.time())
        if now >= expires + leeway:
            raise JWTError("JWT has expired")
    return claims


# --------------------------------------------------------------------------
# JWE: compact serialization, A256GCM content encryption.
# --------------------------------------------------------------------------


class JWEError(ValueError):
    """Raised for a JWE we cannot build or cannot open."""


def ec_public_key_to_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    numbers = key.public_numbers()
    size = (key.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(numbers.x.to_bytes(size, "big")),
        "y": b64u_encode(numbers.y.to_bytes(size, "big")),
    }


def jwk_to_ec_public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    """Validate a relier's `keys_jwk` exactly as `deriver-utils.ts` does.

    Being strict here is deliberate: the point of the check is that a relier
    which fumbles its key generation finds out now, rather than shipping a key
    nobody can decrypt with.
    """
    if jwk.get("kty") != "EC":
        raise JWEError("appJwk is not an EC key")
    if jwk.get("crv") != "P-256":
        raise JWEError("appJwk is not on curve P-256")
    if "d" in jwk:
        raise JWEError("appJwk includes the private key")
    try:
        return ec.EllipticCurvePublicNumbers(
            x=uint_b64u(jwk["x"]), y=uint_b64u(jwk["y"]), curve=ec.SECP256R1()
        ).public_key()
    except (KeyError, ValueError) as exc:
        raise JWEError("invalid EC public key") from exc


def concat_kdf(
    shared_secret: bytes,
    algorithm_id: bytes,
    apu: bytes = b"",
    apv: bytes = b"",
    length: int = CEK_LENGTH,
) -> bytes:
    """NIST SP 800-56A concat KDF, as RFC 7518 §4.6.2 profiles it for ECDH-ES.

    `length` is baked into the hash input as SuppPubInfo, so asking for a
    prefix of a longer derivation is not the same as deriving that length.
    """
    bits = length * 8
    suffix = (
        _length_prefixed(algorithm_id)
        + _length_prefixed(apu)
        + _length_prefixed(apv)
        + struct.pack(">I", bits)
    )
    out = b""
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(struct.pack(">I", counter) + shared_secret + suffix).digest()
        counter += 1
    return out[:length]


def encrypt_jwe_ecdh_es(
    recipient_jwk: Mapping[str, Any],
    plaintext: bytes,
    *,
    apu: bytes = b"",
    apv: bytes = b"",
) -> str:
    """Encrypt to a P-256 public JWK with ECDH-ES direct key agreement.

    This is the `keys_jwe` blob. We agree a key with an ephemeral keypair, throw
    our half away, and never hold anything that could decrypt it again — the
    auth server stores the blob and hands it back at token time, nothing more.
    """
    recipient = jwk_to_ec_public_key(recipient_jwk)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    cek = concat_kdf(
        ephemeral.exchange(ec.ECDH(), recipient),
        CONTENT_ENCRYPTION.encode("ascii"),
        apu,
        apv,
    )
    header: dict[str, Any] = {
        "alg": "ECDH-ES",
        "enc": CONTENT_ENCRYPTION,
        "epk": ec_public_key_to_jwk(ephemeral.public_key()),
    }
    if apu:
        header["apu"] = b64u_encode(apu)
    if apv:
        header["apv"] = b64u_encode(apv)
    if "kid" in recipient_jwk:
        header["kid"] = recipient_jwk["kid"]
    return _seal(header, cek, plaintext)


def encrypt_jwe_dir(cek: bytes, plaintext: bytes, *, kid: str | None = None) -> str:
    """Encrypt under a pre-shared key — `fxa-auth-client`'s `jweEncrypt`."""
    header: dict[str, Any] = {"enc": CONTENT_ENCRYPTION, "alg": "dir"}
    if kid is not None:
        header["kid"] = kid
    return _seal(header, cek, plaintext)


def decrypt_jwe(jwe: str, key: bytes | ec.EllipticCurvePrivateKey) -> bytes:
    """Open a compact JWE, taking a raw CEK for `dir` or a P-256 private key for ECDH-ES."""
    parts = jwe.split(".")
    if len(parts) != 5:
        raise JWEError(f"expected 5 JWE segments, got {len(parts)}")
    protected, encrypted_key, iv, ciphertext, tag = parts
    try:
        header = json.loads(b64u_decode(protected))
    except ValueError as exc:
        raise JWEError("malformed JWE header") from exc
    if header.get("enc") != CONTENT_ENCRYPTION:
        raise JWEError(f"unsupported content encryption: {header.get('enc')!r}")

    algorithm = header.get("alg")
    if algorithm == "dir":
        if not isinstance(key, bytes):
            raise JWEError("alg=dir needs the content encryption key")
        cek = key
    elif algorithm == "ECDH-ES":
        if isinstance(key, bytes):
            raise JWEError("alg=ECDH-ES needs an EC private key")
        if encrypted_key:
            raise JWEError("ECDH-ES direct agreement carries no encrypted key")
        cek = concat_kdf(
            key.exchange(ec.ECDH(), jwk_to_ec_public_key(header.get("epk", {}))),
            CONTENT_ENCRYPTION.encode("ascii"),
            b64u_decode(header["apu"]) if "apu" in header else b"",
            b64u_decode(header["apv"]) if "apv" in header else b"",
        )
    else:
        raise JWEError(f"unsupported JWE algorithm: {algorithm!r}")

    try:
        return AESGCM(cek).decrypt(
            b64u_decode(iv),
            b64u_decode(ciphertext) + b64u_decode(tag),
            protected.encode("ascii"),
        )
    except InvalidTag as exc:
        raise JWEError("JWE authentication failed") from exc


def _seal(header: Mapping[str, Any], cek: bytes, plaintext: bytes) -> str:
    if len(cek) != CEK_LENGTH:
        raise JWEError(f"A256GCM needs a {CEK_LENGTH}-byte key, got {len(cek)}")
    protected = _b64u_json(header)
    iv = os.urandom(IV_LENGTH)
    # The header is authenticated but not encrypted, so a tampered `epk` fails here.
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    ciphertext, tag = sealed[:-TAG_LENGTH], sealed[-TAG_LENGTH:]
    # Empty second segment: direct agreement means there is no wrapped key.
    return f"{protected}..{b64u_encode(iv)}.{b64u_encode(ciphertext)}.{b64u_encode(tag)}"


def _b64u_json(value: Mapping[str, Any]) -> str:
    return b64u_encode(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data
