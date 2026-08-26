# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""tokenlib: the credential the tokenserver hands out and Sync storage checks.

`syncstorage-rs/tokenserver-auth/src/token/native.rs`, itself a port of
mozilla-services/tokenlib.  The tokenserver mints a pair — an opaque `id` and a
`key` — and the client HAWK-signs its storage requests with them.  Storage
never talks to the tokenserver: it re-derives the same key from the shared
secret and the token's own contents, so the token *is* the authorization.

    payload  = JSON of the claims plus a 3-byte hex `salt`
    id       = base64url(payload || HMAC-SHA256(signing_key, payload))
    key      = base64url(HKDF(secret, salt=salt_ascii, info=derive_info + id))

Three details are load-bearing and easy to get wrong:

* the base64 here is URL-safe **with** padding, unlike every other base64url in
  this codebase — `general_purpose::URL_SAFE`, not `URL_SAFE_NO_PAD`;
* the derive info ends with the base64 token text itself, so the key is bound
  to the exact bytes of the id;
* the HKDF salt is the ASCII of the hex salt string, not the 3 bytes it spells.

The two info strings are frozen constants upstream, quoted from tokenlib, and
changing either would strand every outstanding token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..crypto.hkdf import hkdf

#: tokenlib's own constants; see the module docstring.
SIGNING_INFO = b"services.mozilla.com/tokenlib/v1/signing"
DERIVE_INFO = b"services.mozilla.com/tokenlib/v1/derive/"

#: Info string for the shared secret fxa-lite derives when none is configured.
SECRET_INFO = b"fxa-lite/tokenserver-shared-secret"

MAC_LENGTH = hashlib.sha256().digest_size


def signing_key(secret: str) -> bytes:
    """The HMAC key both tiers derive from the shared secret."""
    return hkdf(secret.encode(), SIGNING_INFO)


def make_token(claims: dict[str, Any], secret: str) -> tuple[str, str]:
    """Return `(id, key)` for these claims — the tokenserver's whole output.

    The salt is fresh per token, which is what keeps two tokens issued for the
    same user in the same second from sharing a HAWK key.
    """
    salt = secrets.token_bytes(3).hex()
    payload = json.dumps({**claims, "salt": salt}, separators=(",", ":")).encode()
    mac = hmac.new(signing_key(secret), payload, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload + mac).decode("ascii")
    return token, derive_secret(token, salt, secret)


def derive_secret(token: str, salt: str, secret: str) -> str:
    """The per-token HAWK key. Storage recomputes this from the token it is shown."""
    derived = hkdf(secret.encode(), DERIVE_INFO + token.encode("ascii"), salt=salt.encode("ascii"))
    return base64.urlsafe_b64encode(derived).decode("ascii")


# DIVERGENCE: tokenserver-secret-derived — the shared secret falls out of the signing key
#   upstream: `tokenserver_shared_secret` must be configured, because the
#     tokenserver and the storage node are separate deployments that have to be
#     told the same string.
#   fxa-lite: absent an explicit value, it is HKDF'd from the OAuth signing key
#     under `fxa-lite/tokenserver-shared-secret`.
#   why: the two tiers are one process here, so there is nobody to agree with,
#     and a second secret to manage is a second secret to lose. Deriving it ties
#     its rotation to the signing key's, which is the right coupling.
#   cost: rotating the signing key invalidates outstanding Sync tokens as well
#     as outstanding JWTs. That costs a client one extra request. The derivation
#     is domain-separated: `SECRET_INFO` appears nowhere else, and the key's only
#     other use is RS256.
def resolve_shared_secret(configured: str | None, private_key: rsa.RSAPrivateKey) -> str:
    """The secret the tokenserver and storage tiers share.

    Upstream this must be configured, because the two tiers are separate
    deployments that have to be told the same string.  In fxa-lite they are the
    same process, so there is nobody to agree with: absent an explicit
    `tokenserver_shared_secret`, one is derived from the OAuth signing key.
    That keeps it stable across restarts without a second secret to manage, and
    ties its rotation to the signing key's — which is the right coupling, since
    rotating either one only costs clients a fresh token.
    """
    if configured:
        return configured
    material = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(hkdf(material, SECRET_INFO)).decode("ascii")


def metrics_hash(value: str, secret: str) -> str:
    """`fxa_metrics_hash` — an HMAC, truncated to 32 hex characters.

    The reference keys this with a dedicated `fxa_metrics_hash_secret` so that
    the analytics pipeline can correlate events without ever holding a uid.
    fxa-lite has no analytics pipeline; the value still has to be *some*
    one-way function of the uid because it goes on the wire and into the token,
    so it is keyed with the tokenserver secret rather than adding a second
    knob that would only ever be set to a random string.
    """
    digest = hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
    return digest[:32]


def hashed_device_id(hashed_fxa_uid: str, secret: str) -> str:
    """`hash_device_id` — the hashed uid with `"none"` appended, hashed again.

    The literal `"none"` is upstream's placeholder for the device id that used
    to come from BrowserID (syncstorage-rs #1663), and it is applied to the
    already-hashed uid despite the parameter there being named `fxa_uid`.
    """
    return metrics_hash(hashed_fxa_uid + "none", secret)


__all__ = [
    "DERIVE_INFO",
    "MAC_LENGTH",
    "SIGNING_INFO",
    "derive_secret",
    "hashed_device_id",
    "make_token",
    "metrics_hash",
    "resolve_shared_secret",
    "signing_key",
]
