"""Deciding what a client may have, and minting the tokens that say so.

`lib/oauth/grant.js` plus `lib/oauth/jwt_access_token.js`, with one structural
change the plan calls for: upstream, the auth server signs an HS256 "assertion"
about the session and immediately POSTs it to itself so the OAuth server can
verify it (`makeAssertionJWT` → `verifyAssertion`).  That round trip exists
because the two used to be separate services.  Here they are one function call,
and `SessionClaims` is the assertion's payload passed directly.

The output side is unchanged and has to be: a JWT access token signed with our
RSA key, `typ: at+JWT`, and — the one claim that matters most — an `aud` of the
**tokenserver URL** rather than the client id whenever the scope includes
`apps/oldsync`.  Sync's whole authorization chain hangs off that.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from .. import errors
from ..db import Account, Database, RefreshToken, SessionToken
from .clients import KEY_BEARING_SCOPES, OLDSYNC_SCOPE, Client
from .keys import SigningKeys
from .scopes import ScopeSet

#: `at+JWT` from RFC 9068: what tells a resource server this is an access token
#: and not an ID token that happens to verify.
ACCESS_TOKEN_TYP = "at+JWT"  # noqa: S105 - a JOSE `typ` header value

#: `UNTRUSTED_CLIENT_ALLOWED_SCOPES` — all an unregistered relier may ever ask for.
UNTRUSTED_ALLOWED_SCOPES = ScopeSet.from_array(
    ["openid", "profile:uid", "profile:email", "profile:display_name"]
)
#: `TRUSTED_CLIENT_ALLOWED_SCOPES` — granted to a trusted client on top of its own list.
TRUSTED_ALLOWED_SCOPES = ScopeSet.from_array(
    ["openid", "profile", "email", "profile:subscriptions"]
)

#: Scopes that mean "give me a credential right now" and so make no sense to
#: renew from a refresh token (`SCOPES_TO_EXCLUDE_FROM_REFRESH_TOKEN_GRANTS`).
NON_REFRESHABLE_SCOPES = ScopeSet.from_array(
    ["openid", "https://identity.mozilla.com/tokens/session"]
)


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """What `makeAssertionJWT` would have signed about a session token.

    `last_auth_at` is **seconds** — it becomes `auth_at` on the token response
    and `auth_time` on the JWT, both of which are defined in seconds. Every
    other timestamp here is milliseconds, as everywhere else in fxa-lite.
    """

    uid: str
    email: str
    session_token_id: str
    #: `fxa-generation`: the account's `verifierSetAt`. A password change moves
    #: it, which is how a relier notices tokens minted before that change.
    generation: int
    last_auth_at: int
    profile_changed_at: int
    keys_changed_at: int
    #: Sessions here are verified from birth — see `accounts.provision`.
    token_verified: bool = True
    amr: tuple[str, ...] = ("pwd", "email")
    aal: int = 1

    @classmethod
    def for_session(cls, account: Account, token: SessionToken) -> SessionClaims:
        return cls(
            uid=account.uid,
            email=account.email,
            session_token_id=token.token_id,
            generation=account.verifier_set_at,
            last_auth_at=token.last_auth_at,
            profile_changed_at=account.profile_changed_at,
            keys_changed_at=account.keys_changed_at,
        )


@dataclass(frozen=True, slots=True)
class GrantRequest:
    """The parts of an authorization request that bear on what may be granted."""

    scope: ScopeSet
    access_type: str = "online"
    keys_jwe: str | None = None


@dataclass(slots=True)
class Grant:
    """A vetted authorization: who, which client, which scopes, how fresh."""

    client: Client
    uid: str
    email: str
    scope: ScopeSet
    #: Seconds, like `SessionClaims.last_auth_at`.
    auth_at: int
    generation: int
    profile_changed_at: int
    keys_changed_at: int
    amr: tuple[str, ...]
    aal: int
    session_token_id: str | None = None
    keys_jwe: str | None = None
    offline: bool = False
    #: The scopes in this grant that carry a derived key. Populated by
    #: `validate_requested_grant` because deciding it needs the scope table.
    key_bearing: tuple[str, ...] = field(default_factory=tuple)

    @property
    def client_id(self) -> str:
        return self.client.id


# DIVERGENCE: strict-scope-validation — an unregistered scope is dropped, not granted
#   upstream: `strictScopeValidation` is off by default, so a trusted client
#     asking for a scope outside its own allow-list is simply granted it
#     (`lib/oauth/grant.js`).
#   fxa-lite: on. The scope is dropped, and a request every one of whose scopes
#     was dropped is refused rather than answered with an empty grant.
#   why: upstream's default is tolerable while an admin panel curates the client
#     table. Here that table is a config file edited by hand, so the registered
#     allow-list has to be the whole answer.
#   cost: a `[[clients]]` entry with an incomplete `allowed_scopes` gets a
#     narrower grant than it asked for instead of working. `test_security.py`
#     pins that a dropped scope cannot reappear on the refresh path.
def validate_requested_grant(
    claims: SessionClaims, client: Client, request: GrantRequest
) -> Grant:
    """May this client have these scopes for this user? Raises if not.

    Two rules from `validateRequestedGrant`, in the order it applies them:
    an untrusted client is confined to the `profile:*` handful, and a
    key-bearing scope must be in the client's own allow-list — a client that
    could ask for `apps/oldsync` unregistered could ask for the Sync key.

    fxa-lite runs upstream's optional `strictScopeValidation`: a trusted client
    asking for something outside its allow-list has that scope *dropped* rather
    than silently granted. The default upstream is to grant it, which is
    tolerable when an admin panel curates the client table and not when the
    table is a config file.
    """
    scope = request.scope

    if not client.trusted:
        invalid = scope.difference(UNTRUSTED_ALLOWED_SCOPES)
        if not invalid.is_empty():
            raise errors.invalid_scopes(invalid.values())

    # Key-bearing scopes are checked before the trusted-client trim, so asking
    # for one you may not have is an error rather than a quiet omission.
    key_bearing = tuple(value for value in scope.values() if value in KEY_BEARING_SCOPES)
    if key_bearing:
        forbidden = ScopeSet.from_array(key_bearing).difference(client.allowed_scopes)
        if not forbidden.is_empty():
            raise errors.invalid_scopes(forbidden.values())

    if client.trusted:
        allowed = client.allowed_scopes.union(TRUSTED_ALLOWED_SCOPES)
        scope = scope.filtered(allowed)
        if scope.is_empty() and not request.scope.is_empty():
            raise errors.invalid_scopes(request.scope.values())

    return Grant(
        client=client,
        uid=claims.uid,
        email=claims.email,
        scope=scope,
        auth_at=claims.last_auth_at,
        generation=claims.generation,
        profile_changed_at=claims.profile_changed_at,
        keys_changed_at=claims.keys_changed_at,
        amr=claims.amr,
        aal=claims.aal,
        session_token_id=claims.session_token_id,
        keys_jwe=request.keys_jwe,
        offline=request.access_type == "offline",
        key_bearing=key_bearing,
    )


def generate_tokens(
    db: Database,
    grant: Grant,
    *,
    keys: SigningKeys,
    issuer: str,
    tokenserver_url: str,
    ttl: int,
    now_ms: int,
) -> dict[str, Any]:
    """The `/v1/oauth/token` response body: always an access token, sometimes more."""
    access_token = _access_token(
        grant,
        keys=keys,
        issuer=issuer,
        tokenserver_url=tokenserver_url,
        ttl=ttl,
        now_ms=now_ms,
    )
    response: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "bearer",
        "scope": str(grant.scope),
        "expires_in": ttl,
    }
    # A refresh-token grant carries no authentication event, so it reports no
    # `auth_at` rather than a made-up one — same as upstream's `if (grant.authAt)`.
    if grant.auth_at:
        response["auth_at"] = grant.auth_at
    if grant.keys_jwe:
        response["keys_jwe"] = grant.keys_jwe
    if grant.offline:
        response["refresh_token"] = mint_refresh_token(db, grant, now_ms=now_ms)
    # `id_token` (scope=openid) is deliberately absent: nothing fxa-lite serves
    # consumes one, and an OIDC login it cannot fully support is worse than none.
    return response


def mint_refresh_token(db: Database, grant: Grant, *, now_ms: int) -> str:
    """Create a refresh token, storing only its hash. Returns the token itself."""
    token = secrets.token_hex(32)
    db.create_refresh_token(
        RefreshToken(
            token_id=hash_token(token),
            uid=grant.uid,
            client_id=grant.client_id,
            scope=str(grant.scope),
            created_at=now_ms,
            last_used_at=now_ms,
        )
    )
    return token


def hash_token(token: str) -> str:
    """`fxa-shared/auth/encrypt.hash` — sha256 over the token's *hex bytes*.

    Upstream hashes the raw bytes the hex string decodes to. Ours hashes the
    ASCII, which is equally one-way and never crosses a wire, so the two need
    not agree: nothing outside this process ever recomputes it.
    """
    return sha256(token.encode("ascii")).hexdigest()


def _access_token(
    grant: Grant,
    *,
    keys: SigningKeys,
    issuer: str,
    tokenserver_url: str,
    ttl: int,
    now_ms: int,
) -> str:
    issued_at = now_ms // 1000
    claims: dict[str, Any] = {
        # The claim Sync hangs on. `jwt_access_token.js`: when the scope covers
        # apps/oldsync the audience is the tokenserver, not the client — the
        # client is a browser, the token is spent at the tokenserver.
        "aud": tokenserver_url if grant.scope.contains(OLDSYNC_SCOPE) else grant.client_id,
        "client_id": grant.client_id,
        "exp": issued_at + ttl,
        "iat": issued_at,
        "iss": issuer,
        # Upstream this is the id of the access-token row. There is no row here
        # — the TTL is short enough that the JWT is the whole record — so it is
        # just a unique id, which is all `jti` promises.
        "jti": secrets.token_hex(32),
        "scope": str(grant.scope),
        "sub": grant.uid,
    }
    if grant.generation:
        claims["fxa-generation"] = grant.generation
    if grant.profile_changed_at:
        claims["fxa-profileChangedAt"] = grant.profile_changed_at
    if grant.aal:
        claims["acr"] = f"AAL{grant.aal}"
    if grant.auth_at:
        claims["auth_time"] = grant.auth_at
    return keys.sign(claims, typ=ACCESS_TOKEN_TYP)
