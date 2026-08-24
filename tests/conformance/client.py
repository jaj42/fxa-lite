"""A Python port of `fxa-auth-client`, deliberately independent of the server.

Ports `lib/crypto.ts`, `lib/hawk.ts`, `lib/bearer.ts` and the parts of
`lib/client.ts` fxa-lite implements.  Every derivation is written out from the
protocol description rather than imported from `fxa_lite.crypto`, so that a
mistake in one implementation shows up as a test failure instead of as two
modules agreeing on the wrong answer.

The HKDF, PBKDF2 and XOR below are therefore *intentional* duplication.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx

NAMESPACE = "identity.mozilla.com/picl/v1/"
V1_ITERATIONS = 1000

#: `TOKEN_PREFIXES` from `lib/bearer.ts`.
TOKEN_PREFIXES = {
    "sessionToken": "fxs",
    "keyFetchToken": "fxk",
    "accountResetToken": "fxar",
    "passwordForgotToken": "fxpf",
    "passwordChangeToken": "fxpc",
}


def hkdf(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF-SHA256. An absent salt is `hashLen` zero bytes."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def kw(name: str) -> bytes:
    return (NAMESPACE + name).encode()


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), "xor operands must be the same length"
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


@dataclass(frozen=True)
class Credentials:
    """`crypto.getCredentials` — what the browser derives and what it keeps."""

    auth_pw: bytes
    unwrap_b_key: bytes

    @property
    def auth_pw_hex(self) -> str:
        return self.auth_pw.hex()


def get_credentials(email: str, password: str) -> Credentials:
    """v1 key stretching: PBKDF2 salted with the email, then two HKDFs."""
    salt = f"{NAMESPACE}quickStretch:{email}".encode()
    stretched = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, V1_ITERATIONS, dklen=32)
    return Credentials(
        auth_pw=hkdf(stretched, kw("authPW"), 32),
        unwrap_b_key=hkdf(stretched, kw("unwrapBkey"), 32),
    )


@dataclass(frozen=True)
class TokenCredentials:
    """`deriveHawkCredentials` — 96 bytes of HKDF, sliced in three."""

    id: str
    auth_key: bytes
    bundle_key: bytes


def derive_token_credentials(token: str, kind: str) -> TokenCredentials:
    key_material = hkdf(bytes.fromhex(token), kw(kind), 96)
    return TokenCredentials(
        id=key_material[0:32].hex(),
        auth_key=key_material[32:64],
        bundle_key=key_material[64:96],
    )


def bearer_header(token: str, kind: str) -> dict[str, str]:
    """`bearerHeader` — `Bearer fxs_<id>` and friends."""
    credentials = derive_token_credentials(token, kind)
    return {"authorization": f"Bearer {TOKEN_PREFIXES[kind]}_{credentials.id}"}


def hawk_header(token: str, kind: str, *, mac: str | None = None) -> dict[str, str]:
    """The header Firefox Desktop still sends.

    `ts`, `nonce` and `mac` are filled in because a real client fills them in;
    the server is expected to parse the `id` and ignore the rest, so the `mac`
    defaults to something that could not possibly verify.
    """
    credentials = derive_token_credentials(token, kind)
    return {
        "authorization": (
            f'Hawk id="{credentials.id}", ts="{int(time.time())}", '
            f'nonce="{secrets.token_hex(4)}", mac="{mac or secrets.token_hex(16)}"'
        )
    }


def unbundle_key_fetch_response(bundle_key: bytes, bundle: str) -> tuple[bytes, bytes]:
    """`crypto.unbundleKeyFetchResponse`: check the MAC, then undo the one-time pad."""
    payload = bytes.fromhex(bundle)
    ciphertext, mac = payload[:-32], payload[-32:]
    key_material = hkdf(bundle_key, kw("account/keys"), 3 * 32)
    hmac_key, xor_key = key_material[0:32], key_material[32:96]
    expected = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Bad HMAC on key fetch bundle")
    plaintext = xor(ciphertext, xor_key)
    return plaintext[0:32], plaintext[32:64]


def unwrap_kb(wrap_kb: bytes, unwrap_b_key: bytes) -> bytes:
    return xor(wrap_kb, unwrap_b_key)


class ClientError(Exception):
    """An FxA error envelope, raised as an exception. `errno` is the useful part."""

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(f"{status} errno={body.get('errno')}: {body.get('message')}")
        self.status = status
        self.body = body
        self.errno = body.get("errno")
        self.code = body.get("code")
        self.message = body.get("message")


class AuthClient:
    """The subset of `fxa-auth-client` fxa-lite's phase 2 answers."""

    def __init__(self, http: httpx.AsyncClient, prefix: str = "/v1", scheme: str = "bearer"):
        self.http = http
        self.prefix = prefix
        #: 'bearer' or 'hawk'. Both are accepted by the server; tests run both.
        self.scheme = scheme

    async def request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = await self.http.request(
            method, f"{self.prefix}{path}", json=payload, headers=headers
        )
        try:
            body = response.json()
        except ValueError as exc:  # pragma: no cover - a non-JSON body is a bug
            raise ClientError(response.status_code, {"message": response.text}) from exc
        if response.status_code >= 400:
            raise ClientError(response.status_code, body)
        return body

    def authorization(self, token: str, kind: str) -> dict[str, str]:
        if self.scheme == "hawk":
            return hawk_header(token, kind)
        return bearer_header(token, kind)

    async def authed(
        self, method: str, path: str, token: str, kind: str, payload: Any = None
    ) -> Any:
        return await self.request(method, path, payload, self.authorization(token, kind))

    # -- account --------------------------------------------------------------

    async def sign_up(self, email: str, password: str, keys: bool = False) -> dict[str, Any]:
        credentials = get_credentials(email, password)
        account = await self.request(
            "POST",
            _with_keys("/account/create", keys),
            {"email": email, "authPW": credentials.auth_pw_hex},
        )
        if keys:
            account["unwrapBKey"] = credentials.unwrap_b_key
        return account

    async def sign_in(self, email: str, password: str, keys: bool = False) -> dict[str, Any]:
        credentials = get_credentials(email, password)
        account = await self.request(
            "POST",
            _with_keys("/account/login", keys),
            {"email": email, "authPW": credentials.auth_pw_hex},
        )
        if keys:
            account["unwrapBKey"] = credentials.unwrap_b_key
        return account

    async def account_keys(self, key_fetch_token: str, unwrap_b_key: bytes) -> dict[str, bytes]:
        """Fetch, verify and unwrap the key bundle. Returns kA and kB."""
        credentials = derive_token_credentials(key_fetch_token, "keyFetchToken")
        data = await self.authed("GET", "/account/keys", key_fetch_token, "keyFetchToken")
        ka, wrap_kb = unbundle_key_fetch_response(credentials.bundle_key, data["bundle"])
        return {"kA": ka, "kB": unwrap_kb(wrap_kb, unwrap_b_key)}

    async def sign_in_or_up(
        self, email: str = "sync-user@example.com", password: str = "correct horse battery staple"
    ) -> dict[str, Any]:
        """Create the account if it is not there yet, then sign in. Test sugar."""
        try:
            return await self.sign_up(email, password)
        except ClientError as exc:
            if exc.errno != 101:
                raise
        return await self.sign_in(email, password)

    async def account_status(self, uid: str) -> Any:
        return await self.request("GET", f"/account/status?uid={uid}")

    async def account_status_by_email(self, email: str) -> Any:
        return await self.request("POST", "/account/status", {"email": email})

    async def account_profile(self, session_token: str) -> Any:
        return await self.authed("GET", "/account/profile", session_token, "sessionToken")

    async def destroy_account(self, email: str, password: str, session_token: str) -> Any:
        credentials = get_credentials(email, password)
        return await self.authed(
            "POST",
            "/account/destroy",
            session_token,
            "sessionToken",
            {"email": email, "authPW": credentials.auth_pw_hex},
        )

    async def credentials_status(self, email: str) -> Any:
        return await self.request("POST", "/account/credentials/status", {"email": email})

    # -- session --------------------------------------------------------------

    async def recovery_email_status(self, session_token: str) -> Any:
        return await self.authed(
            "GET", "/recovery_email/status", session_token, "sessionToken"
        )

    async def session_status(self, session_token: str) -> Any:
        return await self.authed("GET", "/session/status", session_token, "sessionToken")

    async def session_destroy(self, session_token: str, payload: Any = None) -> Any:
        return await self.authed(
            "POST", "/session/destroy", session_token, "sessionToken", payload or {}
        )

    async def session_duplicate(self, session_token: str) -> Any:
        return await self.authed(
            "POST", "/session/duplicate", session_token, "sessionToken", {}
        )

    async def session_reauth(
        self, session_token: str, email: str, password: str, keys: bool = False
    ) -> dict[str, Any]:
        credentials = get_credentials(email, password)
        result = await self.authed(
            "POST",
            _with_keys("/session/reauth", keys),
            session_token,
            "sessionToken",
            {"email": email, "authPW": credentials.auth_pw_hex},
        )
        if keys:
            result["unwrapBKey"] = credentials.unwrap_b_key
        return result

    # -- devices --------------------------------------------------------------

    async def device_register(self, session_token: str, payload: dict[str, Any]) -> Any:
        return await self.authed(
            "POST", "/account/device", session_token, "sessionToken", payload
        )

    async def devices(self, session_token: str) -> Any:
        return await self.authed("GET", "/account/devices", session_token, "sessionToken")

    async def device_destroy(self, session_token: str, device_id: str) -> Any:
        return await self.authed(
            "POST", "/account/device/destroy", session_token, "sessionToken", {"id": device_id}
        )


def _with_keys(path: str, keys: bool) -> str:
    return f"{path}?keys=true" if keys else path
