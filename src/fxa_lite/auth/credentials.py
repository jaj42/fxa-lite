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

There is a third scheme, and it is only for the device routes:
`Authorization: Bearer <64 hex>` with no `fx*_` prefix is an **OAuth refresh
token**, which is how the mobile browsers authenticate device registration —
they never hold a session token at all.  `refresh_credentials` below is
`lib/routes/auth-schemes/refresh-token.js`, and unlike the other two it does
look the credential up in a different table and does check what the grant is
allowed to do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request

from .. import errors
from ..crypto.tokens import BEARER_PREFIXES, TokenType
from ..db import Account, Database, KeyFetchToken, RefreshToken, SessionToken
from ..oauth.clients import DEVICE_MANAGEMENT_CLIENT_IDS, OLDSYNC_SCOPE, Client
from ..oauth.grant import hash_token
from ..oauth.scopes import ScopeSet
from ..throttle import FailureThrottle

#: Hawk's own limit, from the library the reference vendored.
MAX_HEADER_LENGTH = 4096

_SCHEME_RE = re.compile(r"^(\w+)(?:\s+(.*))?$", re.DOTALL)
#: `key="value"` pairs, comma separated. Hawk's grammar, minus the parts we drop.
_ATTRIBUTE_RE = re.compile(r'(\w+)="([^"\\]*)"\s*(?:,\s*|$)')
_TOKEN_ID_RE = re.compile(r"^[0-9a-f]{64}$")
#: `validators.refreshToken`: a bare 32-byte hex value, `Bearer` and no prefix.
_BEARER_RE = re.compile(r"^[Bb]earer\s+([0-9a-f]{64})$")
#: The scope that lets a refresh token manage devices whatever client holds it.
_OLDSYNC = ScopeSet.from_array([OLDSYNC_SCOPE])


@dataclass(frozen=True, slots=True)
class SessionCredentials:
    token: SessionToken
    account: Account


@dataclass(frozen=True, slots=True)
class KeyFetchCredentials:
    token: KeyFetchToken
    account: Account


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """What a device route knows about its caller, from either credential.

    Upstream lists three strategies on every `/account/device*` route
    (`sessionTokenBearer`, `sessionToken`, `refreshToken`) and the handlers read
    one `credentials` object that may carry either `id` (a session token) or
    `refreshTokenId`.  This is that object: exactly one of `session` and
    `refresh` is set, and `client` comes with the latter.
    """

    account: Account
    session: SessionToken | None = None
    refresh: RefreshToken | None = None
    client: Client | None = None

    @property
    def session_token_id(self) -> str | None:
        return self.session.token_id if self.session else None

    @property
    def refresh_token_id(self) -> str | None:
        return self.refresh.token_id if self.refresh else None


# DIVERGENCE: hawk-macs-unverified — the accounts API discards the HAWK MAC
#   upstream: parses `Hawk id="…"` and throws `mac`, `ts` and `nonce` away
#     (`lib/routes/auth-schemes/hawk-fxa-token.js`). The departure here is from
#     the HAWK specification, not from the reference server.
#   fxa-lite: the same, deliberately. The token id is the credential under both
#     `Hawk` and `Bearer fxs_…`, and neither header grants more than the other.
#   why: a server that verified MACs the reference does not would refuse clients
#     the reference accepts — the one failure this project cannot afford — and
#     the id is 32 bytes of CSPRNG output either way.
#   cost: a captured Authorization header is spendable until the session is
#     destroyed, which is one of the reasons TLS is required rather than advised.
#     Sync *storage* HAWK is a different protocol and is fully verified.
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


def device_credentials(request: Request) -> DeviceCredentials:
    """Dependency for `/account/device*`: a session token *or* a refresh token.

    hapi tries the strategies in the order the route lists them and takes the
    first that authenticates; the only thing that distinguishes them on the wire
    is the shape of the bearer value, so the header decides here and no
    credential is looked up twice.
    """
    header = request.headers.get("authorization")
    match = _BEARER_RE.match(header.strip()) if header else None
    if match is None:
        session = session_credentials(request)
        return DeviceCredentials(account=session.account, session=session.token)
    return refresh_credentials(request, match.group(1))


def refresh_credentials(request: Request, refresh_token: str) -> DeviceCredentials:
    """`schemeRefreshToken` — the token itself is the credential, hashed to its id.

    Two checks upstream makes and this makes with it. The client must still be
    registered and public, because a confidential client reaching a device route
    with a bearer token has got there without proving it is itself. And the
    grant must be entitled to manage devices at all: `DEVICE_MANAGEMENT_CLIENT_IDS`
    or the oldsync scope.
    """
    db = database(request)
    record = db.refresh_token(hash_token(refresh_token))
    if record is None:
        raise errors.unauthorized("Token not found")
    account = db.account(record.uid)
    if account is None:
        raise errors.unauthorized("Token not found")

    client = request.app.state.clients.get(record.client_id)
    if client is None:
        # A grant outliving the `[[clients]]` entry that issued it. Upstream
        # cannot reach this — its clients live in the same database as its
        # tokens — so there is no reference behaviour to match; "get a new
        # token" is the only useful thing to say.
        raise errors.unauthorized("Unknown client")
    if not client.public_client:
        raise errors.client_not_public()
    if record.client_id not in DEVICE_MANAGEMENT_CLIENT_IDS and not ScopeSet.from_string(
        record.scope
    ).intersects(_OLDSYNC):
        raise errors.unauthorized("Token not allowed to manage devices")

    return DeviceCredentials(account=account, refresh=record, client=client)


#: Route annotations. `Annotated` rather than a `Depends(...)` default so the
#: dependency is part of the type, and the parameter needs no default value.
Session = Annotated[SessionCredentials, Depends(session_credentials)]
OptionalSession = Annotated[SessionCredentials | None, Depends(optional_session_credentials)]
KeyFetch = Annotated[KeyFetchCredentials, Depends(key_fetch_credentials)]
DeviceAuth = Annotated[DeviceCredentials, Depends(device_credentials)]
