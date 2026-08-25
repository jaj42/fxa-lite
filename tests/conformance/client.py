"""A Python port of `fxa-auth-client`, deliberately independent of the server.

Ports `lib/crypto.ts`, `lib/hawk.ts`, `lib/bearer.ts` and the parts of
`lib/client.ts` fxa-lite implements.  Every derivation is written out from the
protocol description rather than imported from `fxa_lite.crypto`, so that a
mistake in one implementation shows up as a test failure instead of as two
modules agreeing on the wrong answer.

Phase 3 adds the relier half of the OAuth flow, ported from
`libs/vendored/crypto-relier/src/lib/deriver/{scoped-keys,deriver-utils}.ts`:
PKCE, scoped-key derivation, and the compact ECDH-ES JWE a client builds to
carry its scoped keys home.

Phase 5 adds the Sync tokenserver's client and, more usefully, tokenlib's
*reader* — the half `syncstorage-rs` implements rather than the half fxa-lite
does.  Written out from `token/native.rs` and `web/auth.rs`, it is what proves
the credential fxa-lite mints is one a real storage node would accept.

The HKDF, PBKDF2, XOR, concat-KDF and JWE below are therefore *intentional*
duplication.  Only `cryptography`'s primitives are shared with the server, and
only where the stdlib has no equivalent.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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




# --------------------------------------------------------------------------
# The relier half of the OAuth flow.
# --------------------------------------------------------------------------

OLDSYNC_SCOPE = "https://identity.mozilla.com/apps/oldsync"
FIREFOX_DESKTOP_CLIENT_ID = "5882386c6d801776"
WEBCHANNEL_REDIRECT = "urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256: a random verifier and the challenge derived from it."""
    verifier = b64u(os.urandom(32))
    return verifier, b64u(hashlib.sha256(verifier.encode("ascii")).digest())


def derive_scoped_key(
    *,
    scope: str,
    kb: bytes,
    uid: str,
    key_rotation_secret: str,
    key_rotation_timestamp: int,
) -> dict[str, Any]:
    """`scoped-keys.ts`, written out again from the protocol description.

    Sync is the legacy path — 64 bytes from `kB` alone, with a `kid` naming a
    hash of `kB` — and every other scope is the general one, salted with the uid.
    """
    if scope in (OLDSYNC_SCOPE, "https://identity.thunderbird.net/apps/sync"):
        key_material = hkdf(kb, kw("oldsync"), 64)
        return {
            "kty": "oct",
            "scope": scope,
            "k": b64u(key_material),
            "kid": f"{key_rotation_timestamp}-{b64u(hashlib.sha256(kb).digest()[:16])}",
        }
    key_material = hkdf(
        kb + bytes.fromhex(key_rotation_secret),
        f"{NAMESPACE}scoped_key\n{scope}".encode(),
        48,
        salt=bytes.fromhex(uid),
    )
    seconds = round(key_rotation_timestamp / 1000)
    return {
        "kty": "oct",
        "scope": scope,
        "k": b64u(key_material[16:48]),
        "kid": f"{seconds}-{b64u(key_material[0:16])}",
    }


def concat_kdf(shared: bytes, algorithm: bytes, length: int = 32) -> bytes:
    """NIST SP 800-56A single-step KDF as RFC 7518 §4.6.2 profiles it."""

    def prefixed(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    suffix = prefixed(algorithm) + prefixed(b"") + prefixed(b"") + struct.pack(">I", length * 8)
    out, counter = b"", 1
    while len(out) < length:
        out += hashlib.sha256(struct.pack(">I", counter) + shared + suffix).digest()
        counter += 1
    return out[:length]


def generate_relier_keypair() -> ec.EllipticCurvePrivateKey:
    """The P-256 key a client generates so scoped keys can be sent to it."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(32, "big")),
        "y": b64u(numbers.y.to_bytes(32, "big")),
    }


def jwe_encrypt_ecdh_es(recipient_jwk: dict[str, str], plaintext: bytes) -> str:
    """Compact JWE, `alg=ECDH-ES`, `enc=A256GCM` — what `keys_jwe` is."""
    recipient = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(unb64u(recipient_jwk["x"]), "big"),
        y=int.from_bytes(unb64u(recipient_jwk["y"]), "big"),
        curve=ec.SECP256R1(),
    ).public_key()
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    cek = concat_kdf(ephemeral.exchange(ec.ECDH(), recipient), b"A256GCM")
    header = {
        "alg": "ECDH-ES",
        "enc": "A256GCM",
        "epk": public_jwk(ephemeral),
    }
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    return f"{protected}..{b64u(iv)}.{b64u(sealed[:-16])}.{b64u(sealed[-16:])}"


def jwe_decrypt_ecdh_es(jwe: str, key: ec.EllipticCurvePrivateKey) -> bytes:
    protected, encrypted_key, iv, ciphertext, tag = jwe.split(".")
    assert encrypted_key == "", "ECDH-ES direct agreement wraps no key"
    header = json.loads(unb64u(protected))
    epk = header["epk"]
    peer = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(unb64u(epk["x"]), "big"),
        y=int.from_bytes(unb64u(epk["y"]), "big"),
        curve=ec.SECP256R1(),
    ).public_key()
    cek = concat_kdf(key.exchange(ec.ECDH(), peer), header["enc"].encode("ascii"))
    return AESGCM(cek).decrypt(unb64u(iv), unb64u(ciphertext) + unb64u(tag), protected.encode())


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and claims, unverified. Use `verify_jwt` before trusting either."""
    header, payload, _ = token.split(".")
    return json.loads(unb64u(header)), json.loads(unb64u(payload))


def verify_jwt(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    """Verify an RS256 JWT against a JWKS document, the way a relier would.

    This is the check the Sync tokenserver will make in phase 5, so it is worth
    a client that does it independently: it proves `/v1/jwks` publishes the key
    that actually signed the token.
    """
    header, claims = decode_jwt(token)
    assert header["alg"] == "RS256", header
    jwk = next(candidate for candidate in jwks["keys"] if candidate["kid"] == header["kid"])
    public = rsa.RSAPublicNumbers(
        e=int.from_bytes(unb64u(jwk["e"]), "big"),
        n=int.from_bytes(unb64u(jwk["n"]), "big"),
    ).public_key()
    signing_input, signature = token.rsplit(".", 1)
    try:
        public.verify(
            unb64u(signature),
            signing_input.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("bad JWT signature") from exc
    return claims


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
        return await self.raw_request(method, f"{self.prefix}{path}", payload, headers)

    async def raw_request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """As `request`, but `path` is absolute — the profile server is not under /v1."""
        response = await self.http.request(method, path, json=payload, headers=headers)
        if response.status_code == 204:
            return None
        try:
            body = response.json()
        except ValueError as exc:  # pragma: no cover - a non-JSON body is a bug
            raise ClientError(response.status_code, {"message": response.text}) from exc
        if response.status_code >= 400:
            raise ClientError(response.status_code, body)
        return body

    def authorization(self, token: str, kind: str) -> dict[str, str]:
        if kind == "refreshToken":
            # The mobile scheme: the refresh token itself, unhashed and
            # unprefixed. There is no HAWK spelling of it — a refresh token has
            # no derived keys to sign with.
            return {"authorization": f"Bearer {token}"}
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

    async def device_register(
        self, token: str, payload: dict[str, Any], kind: str = "sessionToken"
    ) -> Any:
        return await self.authed("POST", "/account/device", token, kind, payload)

    async def devices(self, token: str, kind: str = "sessionToken") -> Any:
        return await self.authed("GET", "/account/devices", token, kind)

    async def devices_notify(
        self, token: str, payload: dict[str, Any], kind: str = "sessionToken"
    ) -> Any:
        return await self.authed("POST", "/account/devices/notify", token, kind, payload)

    async def device_commands(
        self,
        token: str,
        kind: str = "sessionToken",
        *,
        index: int | None = None,
        limit: int | None = None,
    ) -> Any:
        """`deviceCommandsWithRefreshToken` — the poll Firefox for Android makes."""
        query = {
            name: value
            for name, value in (("index", index), ("limit", limit))
            if value is not None
        }
        path = "/account/device/commands"
        if query:
            path += "?" + urlencode(query)
        return await self.authed("GET", path, token, kind)

    async def device_destroy(
        self, token: str, device_id: str, kind: str = "sessionToken"
    ) -> Any:
        return await self.authed(
            "POST", "/account/device/destroy", token, kind, {"id": device_id}
        )

    async def attached_clients(
        self, session_token: str, *, filter_idle_devices_timestamp: int | None = None
    ) -> Any:
        path = "/account/attached_clients"
        if filter_idle_devices_timestamp is not None:
            path += f"?filterIdleDevicesTimestamp={filter_idle_devices_timestamp}"
        return await self.authed("GET", path, session_token, "sessionToken")

    async def attached_oauth_clients(self, session_token: str) -> Any:
        return await self.authed(
            "GET", "/account/attached_oauth_clients", session_token, "sessionToken"
        )

    # -- oauth ----------------------------------------------------------------

    async def oauth_authorization(self, session_token: str, **payload: Any) -> Any:
        return await self.authed(
            "POST", "/oauth/authorization", session_token, "sessionToken", payload
        )

    async def oauth_token(self, **payload: Any) -> Any:
        return await self.request("POST", "/oauth/token", payload)

    async def oauth_token_from_session(self, session_token: str, **payload: Any) -> Any:
        """`grant_type=fxa-credentials`: the session token *is* the credential.

        Upstream authenticates this with either scheme the auth tier accepts,
        so it goes through `authed` like any session-token route rather than
        carrying an assertion in the body.
        """
        return await self.authed(
            "POST",
            "/oauth/token",
            session_token,
            "sessionToken",
            {"grant_type": "fxa-credentials", **payload},
        )

    async def scoped_key_data(self, session_token: str, client_id: str, scope: str) -> Any:
        return await self.authed(
            "POST",
            "/account/scoped-key-data",
            session_token,
            "sessionToken",
            {"client_id": client_id, "scope": scope},
        )

    async def jwks(self) -> Any:
        return await self.request("GET", "/jwks")

    async def client_info(self, client_id: str) -> Any:
        return await self.request("GET", f"/client/{client_id}")

    async def verify_token(self, access_token: str) -> Any:
        return await self.request("POST", "/verify", {"token": access_token})

    async def introspect(self, token: str, token_type_hint: str | None = None) -> Any:
        payload: dict[str, Any] = {"token": token}
        if token_type_hint:
            payload["token_type_hint"] = token_type_hint
        return await self.request("POST", "/introspect", payload)

    async def destroy_token(self, token: str, **payload: Any) -> Any:
        return await self.request("POST", "/oauth/destroy", {"token": token, **payload})

    async def destroy_token_legacy(self, **payload: Any) -> Any:
        """`POST /v1/destroy` — the spelling Firefox for Android uses."""
        return await self.request("POST", "/destroy", payload)

    # -- profile --------------------------------------------------------------

    async def profile(self, access_token: str, path: str = "/profile") -> Any:
        return await self.raw_request(
            "GET", f"/profile/v1{path}", headers={"authorization": f"Bearer {access_token}"}
        )

    # -- discovery ------------------------------------------------------------

    async def client_configuration(self) -> Any:
        return await self.raw_request("GET", "/.well-known/fxa-client-configuration")

    async def openid_configuration(self) -> Any:
        return await self.raw_request("GET", "/.well-known/openid-configuration")

    # -- the whole flow -------------------------------------------------------

    async def sync_sign_in(
        self,
        email: str,
        password: str,
        *,
        client_id: str = FIREFOX_DESKTOP_CLIENT_ID,
        scope: str | None = None,
        service: str | None = "sync",
        access_type: str = "offline",
    ) -> SyncGrant:
        """Everything a browser does between "password typed" and "has a Sync key".

        Sign in with `keys=true`, fetch and unwrap `kB`, ask which key rotation
        the scopes are on, derive the scoped keys, seal them to a freshly
        generated P-256 key, exchange the lot for a code and then a token, and
        finally open the `keys_jwe` that came back.
        """
        account = await self.sign_in(email, password, keys=True)
        keys = await self.account_keys(account["keyFetchToken"], account["unwrapBKey"])
        session_token = account["sessionToken"]
        uid = account["uid"]

        key_scope = scope or OLDSYNC_SCOPE
        metadata = await self.scoped_key_data(session_token, client_id, key_scope)
        scoped_keys = {
            value: derive_scoped_key(
                scope=value,
                kb=keys["kB"],
                uid=uid,
                key_rotation_secret=entry["keyRotationSecret"],
                key_rotation_timestamp=entry["keyRotationTimestamp"],
            )
            for value, entry in metadata.items()
        }

        relier_key = generate_relier_keypair()
        keys_jwe = jwe_encrypt_ecdh_es(
            public_jwk(relier_key), json.dumps(scoped_keys, separators=(",", ":")).encode()
        )
        verifier, challenge = pkce_pair()
        state = b64u(os.urandom(16))
        authorization = await self.oauth_authorization(
            session_token,
            client_id=client_id,
            state=state,
            access_type=access_type,
            code_challenge=challenge,
            code_challenge_method="S256",
            keys_jwe=keys_jwe,
            **({"scope": scope} if scope else {}),
            **({"service": service} if service and not scope else {}),
        )
        token = await self.oauth_token(
            client_id=client_id,
            code=authorization["code"],
            code_verifier=verifier,
        )
        recovered = json.loads(jwe_decrypt_ecdh_es(token["keys_jwe"], relier_key))
        return SyncGrant(
            account=account,
            keys=keys,
            session_token=session_token,
            state=state,
            authorization=authorization,
            token=token,
            scoped_keys=scoped_keys,
            recovered_keys=recovered,
        )


@dataclass(frozen=True)
class SyncGrant:
    """Everything `sync_sign_in` collected, for a test to make assertions about."""

    account: dict[str, Any]
    keys: dict[str, bytes]
    session_token: str
    state: str
    authorization: dict[str, Any]
    token: dict[str, Any]
    #: What the client derived before sealing it into `keys_jwe`.
    scoped_keys: dict[str, Any]
    #: What came back out of the `keys_jwe` the server echoed.
    recovered_keys: dict[str, Any]

    @property
    def access_token(self) -> str:
        return self.token["access_token"]


def _with_keys(path: str, keys: bool) -> str:
    return f"{path}?keys=true" if keys else path


# --------------------------------------------------------------------------
# The Sync tokenserver, and tokenlib from the storage tier's side.
# --------------------------------------------------------------------------

TOKENLIB_SIGNING_INFO = b"services.mozilla.com/tokenlib/v1/signing"
TOKENLIB_DERIVE_INFO = b"services.mozilla.com/tokenlib/v1/derive/"


class TokenserverError(Exception):
    """The tokenserver's envelope, which is not the accounts API's.

    `status` is the field with meaning — `invalid-client-state` and friends —
    and there is no `errno` anywhere in it.
    """

    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        errors = body.get("errors") or [{}]
        super().__init__(f"{status_code} {body.get('status')}: {errors[0].get('description')}")
        self.status_code = status_code
        self.body = body
        self.status = body.get("status")
        self.description = errors[0].get("description")
        self.name = errors[0].get("name")
        self.location = errors[0].get("location")


def parse_sync_token(token: str, secret: str) -> dict[str, Any]:
    """Verify a tokenlib token and return its claims — `HawkPayload::extract_and_validate`.

    Note the padded URL-safe base64: tokenlib is the one place in this protocol
    that does not strip `=`.
    """
    raw = base64.urlsafe_b64decode(token)
    if len(raw) <= 32:
        raise ValueError("tokenlib token is too short to carry a signature")
    payload, signature = raw[:-32], raw[-32:]
    key = hkdf(secret.encode(), TOKENLIB_SIGNING_INFO, 32)
    if not hmac.compare_digest(hmac.new(key, payload, hashlib.sha256).digest(), signature):
        raise ValueError("bad tokenlib signature")
    return json.loads(payload)


def derive_sync_key(token: str, salt: str, secret: str) -> str:
    """The HAWK key storage recomputes from the token it is shown."""
    derived = hkdf(
        secret.encode(), TOKENLIB_DERIVE_INFO + token.encode("ascii"), 32, salt=salt.encode("ascii")
    )
    return base64.urlsafe_b64encode(derived).decode("ascii")


class TokenserverClient:
    """`GET /token/1.0/sync/1.5` — the one call the Sync tokenserver answers."""

    def __init__(self, http: httpx.AsyncClient, prefix: str = "/token") -> None:
        self.http = http
        self.prefix = prefix

    async def token(
        self,
        access_token: str,
        key_id: str,
        *,
        client_state: str | None = None,
        duration: int | None = None,
        path: str = "/1.0/sync/1.5",
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {access_token}", "X-KeyID": key_id}
        if client_state is not None:
            headers["X-Client-State"] = client_state
        params = {} if duration is None else {"duration": str(duration)}
        response = await self.http.get(
            f"{self.prefix}{path}", headers=headers, params=params
        )
        try:
            body = response.json()
        except ValueError as exc:  # pragma: no cover - a non-JSON body is a bug
            raise TokenserverError(response.status_code, {"status": response.text}) from exc
        if response.status_code >= 400:
            raise TokenserverError(response.status_code, body)
        return body


def sync_key_id(scoped_key: dict[str, Any]) -> str:
    """`X-KeyID` is the oldsync scoped key's own `kid`, unchanged.

    Firefox does not build this header: it hands over the `kid` it already has
    from `keys_jwe`, which is why the tokenserver can compare client states at
    all — both sides are naming `sha256(kB)[:16]`.
    """
    return str(scoped_key["kid"])



# --------------------------------------------------------------------------
# Sync 1.5 storage, from the client's side.
# --------------------------------------------------------------------------
#
# Phase 6's independent implementation.  Unlike the accounts API's HAWK — which
# neither fxa-lite nor Mozilla verifies — this one is checked byte for byte, so
# the client below has to build the normalized string correctly or nothing
# passes.  It is written out from the HAWK specification and
# `syncserver/src/web/auth.rs` rather than shared with `fxa_lite.syncstorage`.

#: The normalized string HAWK takes its MAC over. Every field is significant;
#: the trailing newline is too.
HAWK_HEADER_PREFIX = "hawk.1.header"
HAWK_PAYLOAD_PREFIX = "hawk.1.payload"


def hawk_payload_hash(body: bytes, content_type: str) -> str:
    """`base64(sha256("hawk.1.payload\\n<type>\\n<body>\\n"))`, media type only."""
    media = content_type.partition(";")[0].strip().lower()
    prefix = f"{HAWK_PAYLOAD_PREFIX}\n{media}\n".encode()
    return base64.b64encode(hashlib.sha256(prefix + body + b"\n").digest()).decode()


def hawk_storage_header(
    *,
    token_id: str,
    key: str,
    method: str,
    resource: str,
    host: str,
    port: int,
    body: bytes | None = None,
    content_type: str = "",
    ts: int | None = None,
    nonce: str | None = None,
) -> str:
    """Sign one storage request. `resource` is the path *with* its query string."""
    ts = int(time.time()) if ts is None else ts
    nonce = secrets.token_urlsafe(6) if nonce is None else nonce
    payload_hash = hawk_payload_hash(body, content_type) if body is not None else ""
    normalized = (
        "\n".join(
            [
                HAWK_HEADER_PREFIX,
                str(ts),
                nonce,
                method.upper(),
                resource,
                host.lower(),
                str(port),
                payload_hash,
                "",
            ]
        )
        + "\n"
    )
    mac = base64.b64encode(
        hmac.new(key.encode(), normalized.encode(), hashlib.sha256).digest()
    ).decode()
    header = f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", mac="{mac}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    return header


class SyncStorageClient:
    """The storage half of a Sync client, signing every request itself.

    Built from a tokenserver response, exactly as Firefox builds it: the `id`
    and `key` are what the tokenserver handed over, and `api_endpoint` is the
    URL every path here hangs off.
    """

    def __init__(self, http: httpx.AsyncClient, token: dict[str, Any], *, secret: str) -> None:
        self.http = http
        self.token_id = str(token["id"])
        self.key = str(token["key"])
        self.uid = int(token["uid"])
        endpoint = urlsplit(str(token["api_endpoint"]))
        #: The path `api_endpoint` names, e.g. `/storage/1.5/1`.
        self.prefix = endpoint.path
        self.host = endpoint.hostname or "localhost"
        self.port = endpoint.port or (443 if endpoint.scheme == "https" else 80)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content: bytes | None = None,
        content_type: str | None = None,
        headers: dict[str, str] | None = None,
        sign_payload: bool = True,
        retry_on_conflict: bool = True,
    ) -> httpx.Response:
        """Sign and send. `path` is relative to `api_endpoint`.

        A 503 is retried once after a pause, which is what `Retry-After` asks a
        real client to do. Sync refuses a write that cannot move its
        collection's timestamp past the last one, and against an in-process
        SQLite file two writes land inside the same hundredth of a second far
        more often than they do against a database across a network. Waiting
        out the tick is the client's half of that protocol, not a workaround;
        `retry_on_conflict=False` is for the tests that are checking the
        refusal itself.
        """
        for attempt in range(2):
            response = await self._send(
                method,
                path,
                params=params,
                json_body=json_body,
                content=content,
                content_type=content_type,
                headers=headers,
                sign_payload=sign_payload,
            )
            if response.status_code != 503 or not retry_on_conflict or attempt:
                return response
            await asyncio.sleep(0.02)
        return response

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content: bytes | None = None,
        content_type: str | None = None,
        headers: dict[str, str] | None = None,
        sign_payload: bool = True,
    ) -> httpx.Response:
        url = self.http.build_request(method, f"{self.prefix}{path}", params=params).url
        resource = url.raw_path.decode("ascii")

        body: bytes | None = content
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode()
            content_type = content_type or "application/json"
        if body is not None and content_type is None:
            content_type = "application/json"

        authorization = hawk_storage_header(
            token_id=self.token_id,
            key=self.key,
            method=method,
            resource=resource,
            host=self.host,
            port=self.port,
            body=body if (body is not None and sign_payload) else None,
            content_type=content_type or "",
        )
        sent = {"authorization": authorization, **(headers or {})}
        if content_type is not None:
            sent["content-type"] = content_type
        return await self.http.request(method, url, content=body, headers=sent)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)


class SyncStorageError(Exception):
    """Sync 1.5's whole error vocabulary: a status and one integer."""

    def __init__(self, status_code: int, weave: Any) -> None:
        super().__init__(f"{status_code} weave:{weave}")
        self.status_code = status_code
        self.weave = weave


def expect_ok(response: httpx.Response) -> Any:
    """Unwrap a storage response, or raise with the Weave code it carried."""
    if response.status_code >= 400:
        try:
            weave = response.json()
        except ValueError:
            weave = response.text
        raise SyncStorageError(response.status_code, weave)
    return response.json()
