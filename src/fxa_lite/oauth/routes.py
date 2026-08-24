"""The OAuth routes: authorize, exchange, verify, introspect, revoke, publish keys.

Two prefixes live here, both under `/v1`, and the split is upstream's:

* `/v1/oauth/authorization`, `/v1/oauth/token`, `/v1/oauth/destroy` and
  `/v1/account/scoped-key-data` are the **auth-server** flavour — the ones a
  browser calls, authenticated by a session token where authentication is
  needed at all.
* `/v1/verify`, `/v1/introspect`, `/v1/jwks` and `/v1/client/{id}` are the
  **oauth-server** flavour, called by resource servers.

Both raise errors from the OAuth errno table (`errors.OauthErrno`), which is a
different numbering from the accounts API's. That is not an oversight, it is
what clients expect on these paths.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Request

from .. import errors
from ..accounts import now_ms
from ..auth.credentials import Session, database
from ..crypto import jose
from ..crypto.scoped_keys import NULL_KEY_ROTATION_SECRET
from ..db import Account, Database, OauthCode
from .clients import KEYS_CONDITIONAL_SCOPE, SERVICE_SCOPES, Client, Registry
from .grant import (
    NON_REFRESHABLE_SCOPES,
    Grant,
    GrantRequest,
    SessionClaims,
    generate_tokens,
    hash_token,
    validate_requested_grant,
)
from .keys import SigningKeys
from .models import (
    AuthorizationRequest,
    DestroyRequest,
    IntrospectRequest,
    ScopedKeyDataRequest,
    TokenRequest,
    VerifyRequest,
)
from .scopes import InvalidScopeError, ScopeSet

#: The only PKCE method the reference implements. `plain` defeats the point.
PKCE_METHOD = "S256"
#: `MAX_AGE_LEEWAY_SECONDS` — without it a `max_age=0` request can never be
#: satisfied, because the challenge round trip always advances the clock.
MAX_AGE_LEEWAY = 5

GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"

router = APIRouter(tags=["oauth"])


# --------------------------------------------------------------------------
# App state accessors. Everything here is built once, at startup.
# --------------------------------------------------------------------------


def signing_keys(request: Request) -> SigningKeys:
    return request.app.state.signing_keys


def clients(request: Request) -> Registry:
    return request.app.state.clients


def _client(request: Request, client_id: str) -> Client:
    client = clients(request).get(client_id)
    if client is None:
        raise errors.unknown_client(client_id)
    return client


def _tokenserver_url(request: Request) -> str:
    """The `aud` of an oldsync access token, and what Firefox appends `/1.0/sync/1.5` to."""
    return request.app.state.config.url("/token")


def _issuer(request: Request) -> str:
    return request.app.state.config.public_url


# --------------------------------------------------------------------------
# Authorization: session token in, single-use code out.
# --------------------------------------------------------------------------


@router.post("/oauth/authorization")
def oauth_authorization(
    payload: AuthorizationRequest, request: Request, credentials: Session
) -> dict[str, Any]:
    """Turn a signed-in session into an authorization code for `client_id`.

    The browser is the one calling this, through the sign-in page, holding the
    session token it just got from `/v1/account/login`. Everything the OAuth
    server upstream would have learned from a signed assertion is read straight
    off that session here — see `grant.SessionClaims`.
    """
    if payload.response_type != "code":
        raise errors.invalid_response_type()

    db = database(request)
    client = _client(request, payload.client_id)
    redirect_uri = _redirect_uri(client, payload.redirect_uri)
    scope = _requested_scope(payload)
    _check_authentication_strength(payload, credentials.token.last_auth_at)
    _check_pkce_parameters(client, payload)

    claims = SessionClaims.for_session(credentials.account, credentials.token)
    grant = validate_requested_grant(
        claims,
        client,
        GrantRequest(scope=scope, access_type=payload.access_type, keys_jwe=payload.keys_jwe),
    )

    now = now_ms()
    # Abandoned flows leave codes behind. There is no scheduler here, so the
    # sweep rides along with the next authorization; the table is small and the
    # delete is a single indexed comparison.
    db.delete_expired_oauth_codes(now - request.app.state.config.ttl.authorization_code * 1000)

    code = secrets.token_hex(32)
    db.create_oauth_code(
        OauthCode(
            # Stored hashed: a database leak must not hand anyone a redeemable code.
            code=hash_token(code),
            uid=grant.uid,
            client_id=client.id,
            scope=str(grant.scope),
            created_at=now,
            auth_at=credentials.token.auth_at,
            code_challenge=payload.code_challenge,
            code_challenge_method=payload.code_challenge_method,
            keys_jwe=payload.keys_jwe,
            session_token_id=credentials.token.token_id,
            offline=grant.offline,
        )
    )
    return {
        "code": code,
        "state": payload.state,
        "redirect": _redirect_with_code(redirect_uri, code, payload.state),
        # RFC 6749 §5.1: report the granted scope, which may differ from what was
        # asked for — and does, whenever it was resolved from `service=` instead.
        "scope": str(grant.scope),
    }


def _redirect_uri(client: Client, requested: str | None) -> str:
    """Exact match against the client's registered list; no patterns, no prefixes."""
    if requested is None:
        return client.redirect_uri
    if requested not in client.redirect_uris:
        raise errors.incorrect_redirect(requested)
    return requested


def _requested_scope(payload: AuthorizationRequest) -> ScopeSet:
    """`scope=` if given, otherwise resolve `service=` the way ADR 0049 says.

    Firefox sends `service=sync` and no scope at all on the browser flow. The
    resolution is deliberately not restricted to a hard-coded list of browser
    client ids the way upstream restricts it: a client that resolves its way to
    `apps/oldsync` still has to have that scope in its own allow-list, which is
    the check that actually protects the Sync key.
    """
    if payload.scope:
        return _parse_scope(payload.scope, "scope")
    if payload.service:
        resolved = SERVICE_SCOPES.get(payload.service.lower())
        if resolved is None:
            raise errors.oauth_invalid_request_parameter({"keys": ["service"]})
        values = list(resolved)
        # `keys_jwe` present means the user typed their password and the client
        # wrapped scoped keys, so Sync is on the table even for other services.
        if payload.keys_jwe and KEYS_CONDITIONAL_SCOPE not in values:
            values.append(KEYS_CONDITIONAL_SCOPE)
        return ScopeSet.from_array(values)
    raise errors.oauth_invalid_request_parameter({"keys": ["scope"]})


def _parse_scope(value: str, field: str) -> ScopeSet:
    try:
        return ScopeSet.from_string(value)
    except InvalidScopeError as exc:
        raise errors.oauth_invalid_request_parameter({"keys": [field]}) from exc


def _check_authentication_strength(payload: AuthorizationRequest, auth_at: int) -> None:
    """`acr_values` and `max_age`, the two ways a relier asks for a stronger sign-in.

    fxa-lite has one authentication method and no second factor, so `AAL2` can
    never be satisfied and is refused outright rather than answered with the
    errno that sends the frontend off to a 2FA challenge that does not exist.
    """
    if payload.acr_values and "AAL2" in payload.acr_values.split():
        raise errors.mismatch_acr_values("1")
    if payload.max_age is not None and (
        now_ms() // 1000 - auth_at > payload.max_age + MAX_AGE_LEEWAY
    ):
        raise errors.mismatch_acr_values("1")


def _check_pkce_parameters(client: Client, payload: AuthorizationRequest) -> None:
    """PKCE if and only if the client is public — upstream's rule, both halves."""
    if client.public_client:
        if not payload.code_challenge or not payload.code_challenge_method:
            raise errors.missing_pkce_parameters()
    elif payload.code_challenge or payload.code_challenge_method:
        raise errors.not_public_client(client.id)
    if payload.code_challenge_method and payload.code_challenge_method != PKCE_METHOD:
        raise errors.oauth_invalid_request_parameter({"keys": ["code_challenge_method"]})


def _redirect_with_code(redirect_uri: str, code: str, state: str) -> str:
    """`code` and `state` appended as query parameters.

    Works on the `urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel` sentinel
    too, which is not a location at all — the browser reads the parameters off
    it rather than navigating. That is what upstream's `new URL()` does with it.
    """
    parts = urlsplit(redirect_uri)
    query = dict(parse_qsl(parts.query))
    query["code"] = code
    query["state"] = state
    return urlunsplit(parts._replace(query=urlencode(query)))


# --------------------------------------------------------------------------
# Token: code (or refresh token) in, access token out.
# --------------------------------------------------------------------------


@router.post("/oauth/token")
def oauth_token(payload: TokenRequest, request: Request) -> dict[str, Any]:
    db = database(request)
    client = _client(request, payload.client_id)

    config = request.app.state.config

    if payload.grant_type == GRANT_AUTHORIZATION_CODE:
        grant = _authorization_code_grant(db, client, payload, config.ttl.authorization_code)
    elif payload.grant_type == GRANT_REFRESH_TOKEN:
        grant = _refresh_token_grant(db, client, payload)
    else:
        # `fxa-credentials` and RFC 8693 token exchange are out of scope; saying
        # so is better than a 500 from an unreachable branch.
        raise errors.invalid_grant_type()

    ttl = min(payload.ttl or config.ttl.access_token, config.ttl.access_token)
    return generate_tokens(
        db,
        grant,
        keys=signing_keys(request),
        issuer=_issuer(request),
        tokenserver_url=_tokenserver_url(request),
        ttl=ttl,
        now_ms=now_ms(),
    )


def _authorization_code_grant(
    db: Database, client: Client, payload: TokenRequest, code_ttl: int
) -> Grant:
    if payload.code is None:
        raise errors.oauth_invalid_request_parameter({"keys": ["code"]})
    # Checked before the code is even looked up: only a public client has any
    # business presenting a verifier.
    if payload.code_verifier and not client.public_client:
        raise errors.not_public_client(client.id)

    code = db.oauth_code(hash_token(payload.code))
    if code is None:
        raise errors.unknown_code(payload.code)
    if not hmac.compare_digest(code.client_id, client.id):
        raise errors.mismatch_code(payload.code, client.id)

    expires_at = code.created_at + code_ttl * 1000
    if now_ms() > expires_at:
        db.delete_oauth_code(code.code)
        raise errors.expired_code(payload.code, expires_at)

    _check_code_verifier(code, payload.code_verifier)
    # One use only, and spent whether or not the rest of this succeeds.
    db.delete_oauth_code(code.code)

    account = db.account(code.uid)
    if account is None:
        # The account was deleted between authorizing and redeeming.
        raise errors.oauth_invalid_token()
    return _grant_from_code(client, account, code)


def _check_code_verifier(code: OauthCode, verifier: str | None) -> None:
    if code.code_challenge:
        if code.code_challenge_method != PKCE_METHOD:
            raise errors.mismatch_code_challenge(None)
        if not verifier:
            raise errors.missing_pkce_parameters()
        challenge = pkce_challenge(verifier)
        if not hmac.compare_digest(code.code_challenge, challenge):
            raise errors.mismatch_code_challenge(challenge)
    elif verifier:
        # A verifier for a code that was never bound to a challenge: the client
        # is confused about which flow it is in, and proving nothing.
        raise errors.mismatch_code_challenge(pkce_challenge(verifier))


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 S256: base64url(sha256(ascii(verifier))), unpadded."""
    return jose.b64u_encode(sha256(verifier.encode("ascii")).digest())


def _grant_from_code(client: Client, account: Account, code: OauthCode) -> Grant:
    return Grant(
        client=client,
        uid=account.uid,
        email=account.email,
        scope=ScopeSet.from_string(code.scope),
        auth_at=code.auth_at // 1000,
        generation=account.verifier_set_at,
        profile_changed_at=account.profile_changed_at,
        keys_changed_at=account.keys_changed_at,
        amr=("pwd", "email"),
        aal=1,
        session_token_id=code.session_token_id,
        keys_jwe=code.keys_jwe,
        offline=code.offline,
    )


def _refresh_token_grant(db: Database, client: Client, payload: TokenRequest) -> Grant:
    if payload.refresh_token is None:
        raise errors.oauth_invalid_request_parameter({"keys": ["refresh_token"]})
    token = db.refresh_token(hash_token(payload.refresh_token))
    if token is None or not hmac.compare_digest(token.client_id, client.id):
        raise errors.oauth_invalid_token()

    scope = ScopeSet.from_string(token.scope)
    if payload.scope:
        requested = _parse_scope(payload.scope, "scope")
        if not scope.contains(requested):
            # A trusted client may widen the grant, but only within its own
            # allow-list; anyone else is confined to what they already hold.
            allowed = scope.union(client.allowed_scopes) if client.trusted else scope
            if not allowed.contains(requested):
                raise errors.invalid_scopes(requested.difference(scope).values())
        scope = requested
    # `openid` and the session-token scope are one-shot exchanges; renewing them
    # from a long-lived credential would defeat what makes them one-shot.
    scope = scope.difference(NON_REFRESHABLE_SCOPES)

    account = db.account(token.uid)
    if account is None:
        raise errors.oauth_invalid_token()
    db.touch_refresh_token(token.token_id, now_ms())
    return Grant(
        client=client,
        uid=account.uid,
        email=account.email,
        scope=scope,
        # No `auth_at`: this token proves the user authenticated once, not when.
        # The response and the JWT both omit the claim rather than invent one.
        auth_at=0,
        generation=account.verifier_set_at,
        profile_changed_at=account.profile_changed_at,
        keys_changed_at=account.keys_changed_at,
        amr=(),
        aal=0,
        offline=False,
    )


# --------------------------------------------------------------------------
# Scoped key metadata: what a client needs to derive its own key from kB.
# --------------------------------------------------------------------------


@router.post("/account/scoped-key-data")
def scoped_key_data(
    payload: ScopedKeyDataRequest, request: Request, credentials: Session
) -> dict[str, Any]:
    """Per-scope key rotation metadata, for the client that will derive the keys.

    No key material crosses this route. The client already holds `kB`; what it
    is missing is the rotation secret and timestamp that go into the derivation
    (`crypto/scoped_keys.py`), and whether this client is allowed the scope at all.
    """
    client = _client(request, payload.client_id)
    scope = _parse_scope(payload.scope, "scope")
    account = credentials.account
    claims = SessionClaims.for_session(account, credentials.token)
    # This is what refuses a key-bearing scope the client may not have; without
    # it the route would quietly return an empty object instead of an error.
    grant = validate_requested_grant(claims, client, GrantRequest(scope=scope))

    # We never rotate scoped keys, so the secret is the fixed zero buffer
    # upstream uses; the timestamp is the account's own `keysChangedAt`.
    key_rotation_timestamp = max(account.keys_changed_at, 0)
    if claims.last_auth_at < key_rotation_timestamp // 1000:
        # The session predates the rotation it would be deriving keys for.
        raise errors.stale_auth_at(claims.last_auth_at)

    return {
        value: {
            "identifier": value,
            "keyRotationSecret": NULL_KEY_ROTATION_SECRET.hex(),
            "keyRotationTimestamp": key_rotation_timestamp,
        }
        for value in grant.key_bearing
    }


# --------------------------------------------------------------------------
# Resource-server side: verify, introspect, revoke, publish.
# --------------------------------------------------------------------------


@router.get("/jwks")
def jwks(request: Request) -> dict[str, Any]:
    """The public half of the signing key. The Sync tokenserver reads this."""
    return signing_keys(request).jwks


@router.get("/client/{client_id}")
def client_info(client_id: str, request: Request) -> dict[str, Any]:
    client = _client(request, client_id)
    return {
        "id": client.id,
        "name": client.name,
        "trusted": client.trusted,
        "image_uri": client.image_uri,
        "redirect_uri": client.redirect_uri,
    }


@router.post("/verify")
def verify(payload: VerifyRequest, request: Request) -> dict[str, Any]:
    """Who does this access token belong to, and what may it do?

    An access token is a self-contained JWT with a TTL short enough that no
    server-side record is needed, so this is signature and expiry checking and
    nothing else — which is also why the Sync tokenserver can skip the call.
    """
    claims = _verified_access_token(payload.token, request)
    info: dict[str, Any] = {
        "user": claims["sub"],
        "client_id": claims["client_id"],
        "scope": ScopeSet.from_string(claims.get("scope", "")).values(),
    }
    if "fxa-generation" in claims:
        info["generation"] = claims["fxa-generation"]
    if "fxa-profileChangedAt" in claims:
        info["profile_changed_at"] = claims["fxa-profileChangedAt"]
    return info


def _verified_access_token(token: str, request: Request) -> dict[str, Any]:
    try:
        claims = signing_keys(request).verify(token)
    except jose.JWTError as exc:
        if "expired" in str(exc):
            raise errors.expired_token(0) from exc
        raise errors.oauth_invalid_token() from exc
    if jose.decode_jwt_header(token).get("typ") != "at+JWT":
        # An ID token or some other JWT we signed is not an access token.
        raise errors.oauth_invalid_token()
    if claims.get("iss") != _issuer(request) or "sub" not in claims:
        raise errors.oauth_invalid_token()
    return claims


@router.post("/introspect")
def introspect(payload: IntrospectRequest, request: Request) -> dict[str, Any]:
    """RFC 7662. Unlike `/verify`, an inactive token is an answer, not an error."""
    order = ["access_token", "refresh_token"]
    if payload.token_type_hint == "refresh_token":
        order.reverse()
    for token_type in order:
        described = (
            _describe_access_token(payload.token, request)
            if token_type == "access_token"
            else _describe_refresh_token(payload.token, request)
        )
        if described is not None:
            return described
    return {"active": False}


def _describe_access_token(token: str, request: Request) -> dict[str, Any] | None:
    try:
        claims = _verified_access_token(token, request)
    except errors.FxaError:
        return None
    return {
        "active": True,
        "scope": claims.get("scope", ""),
        "client_id": claims["client_id"],
        "token_type": "access_token",
        # Milliseconds, deliberately: `iat`/`exp` have been milliseconds on this
        # endpoint since it shipped, while `auth_time` below is seconds per OIDC.
        # Reliers parse both; "fixing" the units would be the breaking change.
        "iat": claims["iat"] * 1000,
        "exp": claims["exp"] * 1000,
        "sub": claims["sub"],
        "jti": claims["jti"],
        **({"acr": claims["acr"]} if "acr" in claims else {}),
        **({"auth_time": claims["auth_time"]} if "auth_time" in claims else {}),
    }


def _describe_refresh_token(token: str, request: Request) -> dict[str, Any] | None:
    token_id = hash_token(token)
    record = database(request).refresh_token(token_id)
    if record is None:
        return None
    return {
        "active": True,
        "scope": record.scope,
        "client_id": record.client_id,
        "token_type": "refresh_token",
        "iat": record.created_at,
        "sub": record.uid,
        "jti": token_id,
        "fxa-lastUsedAt": record.last_used_at,
    }


@router.post("/oauth/destroy")
def oauth_destroy(payload: DestroyRequest, request: Request) -> dict[str, Any]:
    """RFC 7009 revocation.

    Only refresh tokens are revocable. An access token has no server-side
    record to delete — that is the trade for not having an access-token table —
    so revoking one is a no-op that expires on its own within `ttl.access_token`.
    RFC 7009 §2.2 says to answer 200 either way, which keeps a client from
    treating "already gone" as a failure.
    """
    db = database(request)
    token = db.refresh_token(hash_token(payload.token))
    if token is not None:
        if payload.client_id and not hmac.compare_digest(
            token.client_id, payload.client_id.lower()
        ):
            raise errors.oauth_invalid_token()
        db.delete_refresh_token(token.token_id)
    return {}


__all__ = ["pkce_challenge", "router"]
