"""Turning a HAWK header into a Sync uid.

`syncserver/src/web/{auth,extractors/hawk_identifier}.rs`.

The tokenserver minted this credential and never told anyone; storage rebuilds
it from the token the client presents plus the shared secret:

    id      = base64url(claims || HMAC-SHA256(signing_key, claims))
    key     = base64url(HKDF(secret, salt=claims.salt, info=derive_info + id))

So the check is: the claims are ours (their HMAC verifies), they have not
expired, the key derived from them signs this exact request, and the uid they
name is the uid in the URL. Nothing is looked up; the token *is* the session.

The last of those is easy to skip and is the one that matters most — without
it, any valid token would authorize a request against any other user's
storage, because the path is what selects the data.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..tokenserver import tokenlib
from . import errors, hawk

#: `is_info_collections_path`: the one endpoint served on an expired token.
#: A client whose credential has lapsed can still ask what changed, which is
#: what lets it decide whether a fresh token is worth fetching.
_INFO_COLLECTIONS = ("info", "collections")


@dataclass(frozen=True, slots=True)
class Origin:
    """Host and port as the client signed them — from `public_url`, not `Host`."""

    host: str
    port: int

    @classmethod
    def parse(cls, url: str) -> Origin:
        parts = urlsplit(url)
        host = parts.hostname or "localhost"
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        return cls(host=host, port=port)


@dataclass(frozen=True, slots=True)
class SyncCredentials:
    """A verified tokenlib payload."""

    uid: int
    fxa_uid: str
    fxa_kid: str
    hashed_fxa_uid: str
    hashed_device_id: str
    node: str
    expires: int
    salt: str


def parse_token(token: str, secret: str) -> SyncCredentials:
    """`HawkPayload::extract_and_validate` — decode and authenticate the claims.

    Padded URL-safe base64: tokenlib is the one place in this protocol that
    does not strip `=`, and `base64.urlsafe_b64decode` is forgiving enough to
    accept an unpadded one too, which is fine — the HMAC below is what decides.
    """
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (ValueError, binascii.Error) as exc:
        raise hawk.HawkError("undecodable token id") from exc
    if len(raw) <= tokenlib.MAC_LENGTH:
        raise hawk.HawkError("token id too short to carry a signature")

    payload, signature = raw[: -tokenlib.MAC_LENGTH], raw[-tokenlib.MAC_LENGTH :]
    expected = hmac.new(tokenlib.signing_key(secret), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise hawk.HawkError("bad token signature")

    try:
        claims = json.loads(payload)
    except ValueError as exc:
        raise hawk.HawkError("token payload is not JSON") from exc
    if not isinstance(claims, dict):
        raise hawk.HawkError("token payload is not an object")
    return _credentials(claims)


def _credentials(claims: dict[str, Any]) -> SyncCredentials:
    try:
        uid = claims["uid"]
        salt = claims["salt"]
        # `expires` is seconds and is a float upstream, since the Python
        # tokenserver wrote it as one; rounded, as `extract_and_validate` does.
        expires = round(float(claims["expires"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise hawk.HawkError("token payload is missing a required claim") from exc
    if not isinstance(uid, int) or isinstance(uid, bool) or not isinstance(salt, str):
        raise hawk.HawkError("token payload has a malformed claim")
    return SyncCredentials(
        uid=uid,
        fxa_uid=str(claims.get("fxa_uid", "")),
        fxa_kid=str(claims.get("fxa_kid", "")),
        hashed_fxa_uid=str(claims.get("hashed_fxa_uid", "")),
        hashed_device_id=str(claims.get("hashed_device_id", "")),
        node=str(claims.get("node", "")),
        expires=expires,
        salt=salt,
    )


def authenticate(
    *,
    header: str | None,
    secret: str,
    method: str,
    resource: str,
    path: str,
    origin: Origin,
    now: int,
    body: bytes | None = None,
    content_type: str = "",
) -> SyncCredentials:
    """Verify one request. `resource` is the path with its query, `now` seconds."""
    if not header:
        raise errors.unauthorized()
    try:
        parsed = hawk.parse(header)
        credentials = parse_token(parsed.id, secret)
        if not _exempt_from_expiry(path) and credentials.expires <= now:
            raise hawk.HawkError("token expired")
        key = tokenlib.derive_secret(parsed.id, credentials.salt, secret)
        hawk.verify(
            parsed,
            key,
            method=method,
            resource=resource,
            host=origin.host,
            port=origin.port,
            now=now,
            body=body,
            content_type=content_type,
        )
    except hawk.HawkError as exc:
        raise errors.unauthorized() from exc
    return credentials


def _exempt_from_expiry(path: str) -> bool:
    """`/1.5/{uid}/info/collections`, and only it, matched on all five segments.

    The suffix alone would also match `/1.5/{uid}/storage/info/collections` —
    a BSO called `collections` in a collection called `info` — which is a
    writable resource and must not be reachable with a dead token.
    """
    segments = path.strip("/").split("/")
    return (
        len(segments) == 4
        and segments[0] == "1.5"
        and bool(segments[1])
        and tuple(segments[2:4]) == _INFO_COLLECTIONS
    )


__all__ = ["Origin", "SyncCredentials", "authenticate", "parse_token"]
