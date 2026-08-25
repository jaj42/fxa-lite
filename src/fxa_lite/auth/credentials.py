"""Authenticating a request: two header schemes, one lookup, no MAC.

`Authorization: Hawk id="<tokenId>", ts="…", nonce="…", mac="…"` is what
Firefox Desktop still sends; `Authorization: Bearer fxs_<tokenId>` is what
newer clients send after ADR-0022.  Both carry the same thing — the token id —
and the reference server treats them the same way: parse out the id, look it
up, done (`lib/routes/auth-schemes/hawk-fxa-token.js` explicitly discards
`mac`, `ts` and `nonce`).

We do not verify HAWK MACs either.  It is tempting to "improve" on that, but a
server that verifies MACs the reference does not would reject clients the
reference accepts, and the id is 32 bytes of CSPRNG output either way.  Sync
*storage* HAWK is a different protocol and is fully verified — see phase 6.

Every failure answers 401 / errno 110, whatever went wrong.  That is the
reference's own choice: a malformed header and an expired token are the same
instruction to the client — get a new token.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request

from .. import errors
from ..crypto.tokens import BEARER_PREFIXES, TokenType
from ..db import Account, Database, KeyFetchToken, SessionToken
from ..throttle import FailureThrottle

#: Hawk's own limit, from the library the reference vendored.
MAX_HEADER_LENGTH = 4096

_SCHEME_RE = re.compile(r"^(\w+)(?:\s+(.*))?$", re.DOTALL)
#: `key="value"` pairs, comma separated. Hawk's grammar, minus the parts we drop.
_ATTRIBUTE_RE = re.compile(r'(\w+)="([^"\\]*)"\s*(?:,\s*|$)')
_TOKEN_ID_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class SessionCredentials:
    token: SessionToken
    account: Account


@dataclass(frozen=True, slots=True)
class KeyFetchCredentials:
    token: KeyFetchToken
    account: Account


def token_id(header: str | None, token_type: TokenType) -> str | None:
    """Extract the token id from an Authorization header, or None if there isn't one.

    None means "no credentials offered"; a malformed header raises.
    """
    if not header:
        return None
    if len(header) > MAX_HEADER_LENGTH:
        raise errors.unauthorized("Header length too long")

    match = _SCHEME_RE.match(header.strip())
    if not match:
        raise errors.unauthorized("Invalid header syntax")
    scheme, rest = match.group(1).lower(), match.group(2) or ""

    if scheme == "hawk":
        return _hawk_id(rest)
    if scheme == "bearer":
        return _bearer_id(rest, token_type)
    raise errors.unauthorized(f"Unsupported authentication scheme: {scheme}")


def _hawk_id(attributes: str) -> str:
    found = dict(_ATTRIBUTE_RE.findall(attributes))
    identifier = found.get("id", "")
    if not _TOKEN_ID_RE.match(identifier):
        raise errors.unauthorized("Invalid token id")
    return identifier


def _bearer_id(body: str, token_type: TokenType) -> str:
    prefix = BEARER_PREFIXES[token_type]
    # Strict on purpose: `Bearer <hex>` with no prefix is an OAuth refresh
    # token, a different credential entirely, and must not resolve here.
    match = re.match(rf"^{prefix}_([0-9a-f]{{64}})$", body)
    if not match:
        raise errors.unauthorized("Invalid token id")
    return match.group(1)


def database(request: Request) -> Database:
    return request.app.state.db


def throttle(request: Request) -> FailureThrottle:
    """The failed-password counter every route that stretches one must consult."""
    return request.app.state.throttle


def session_credentials(request: Request) -> SessionCredentials:
    """Dependency for routes authenticated by a session token."""
    credentials = optional_session_credentials(request)
    if credentials is None:
        raise errors.unauthorized("Token not found")
    return credentials


def optional_session_credentials(request: Request) -> SessionCredentials | None:
    """As above, but a request with no Authorization header is allowed through."""
    identifier = token_id(request.headers.get("authorization"), TokenType.SESSION)
    if identifier is None:
        return None
    db = database(request)
    token = db.session_token(identifier)
    if token is None:
        raise errors.unauthorized("Token not found")
    account = db.account(token.uid)
    if account is None:
        # The account was deleted out from under a live session.
        raise errors.unauthorized("Token not found")
    return SessionCredentials(token=token, account=account)


def key_fetch_credentials(request: Request) -> KeyFetchCredentials:
    """Dependency for `GET /v1/account/keys`, the only key-fetch-authed route."""
    identifier = token_id(request.headers.get("authorization"), TokenType.KEY_FETCH)
    if identifier is None:
        raise errors.unauthorized("Token not found")
    db = database(request)
    token = db.key_fetch_token(identifier)
    if token is None:
        raise errors.unauthorized("Token not found")
    account = db.account(token.uid)
    if account is None:
        raise errors.unauthorized("Token not found")
    return KeyFetchCredentials(token=token, account=account)


#: Route annotations. `Annotated` rather than a `Depends(...)` default so the
#: dependency is part of the type, and the parameter needs no default value.
Session = Annotated[SessionCredentials, Depends(session_credentials)]
OptionalSession = Annotated[SessionCredentials | None, Depends(optional_session_credentials)]
KeyFetch = Annotated[KeyFetchCredentials, Depends(key_fetch_credentials)]
