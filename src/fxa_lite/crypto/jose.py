"""JOSE bits: base64url, RSA JWK <-> key conversion, signing-key generation.

RS256 JWT sign/verify and the ECDH-ES+A256GCM compact JWE land here in phase 1;
what exists now is only what `fxa-lite keygen` and `/v1/jwks` need.

Key generation mirrors `packages/fxa-auth-server/lib/oauth/keys.ts`
(`generatePrivateKey`): RSA-2048, `alg: RS256`, `use: sig`, a `kid` of
``YYYYMMDD-<sha256(pkcs1 public pem)[:8]>`` and an `fxa-createdAt` timestamp
rounded down to the hour.
"""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

MODULUS_BITS = 2048
PUBLIC_EXPONENT = 65537

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
