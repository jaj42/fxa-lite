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

    # -- oauth ----------------------------------------------------------------

    async def oauth_authorization(self, session_token: str, **payload: Any) -> Any:
        return await self.authed(
            "POST", "/oauth/authorization", session_token, "sessionToken", payload
        )

    async def oauth_token(self, **payload: Any) -> Any:
        return await self.request("POST", "/oauth/token", payload)

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

