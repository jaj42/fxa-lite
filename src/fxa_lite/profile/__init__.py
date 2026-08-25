"""The profile server, mounted at `/profile/v1`.

`fxa-profile-server` is a separate process upstream that answers every request
by calling the OAuth server's `/v1/verify` and then the auth server's
`/v1/account/profile` over HTTP.  Here both are local: the access token is
verified against the signing key in memory, and the account is read from the
same SQLite file.

What is missing is missing on purpose.  fxa-lite stores no avatars and no
display names, so those fields are simply absent rather than reported as empty
strings — a client that sees no `displayName` falls back to the email, which
is the right outcome; one that sees `""` renders a blank.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from .. import errors
from ..auth.credentials import database
from ..crypto import jose
from ..db import Account
from ..oauth.scopes import ScopeSet

#: `openid`'s counterpart to `profile:email`; both grant the address.
EMAIL_SCOPES = ("profile:email", "email")
UID_SCOPES = ("profile:uid",)
DISPLAY_NAME_SCOPES = ("profile:display_name",)


@dataclass(frozen=True, slots=True)
class TokenCredentials:
    """A verified access token, plus the account it names."""

    account: Account
    scope: ScopeSet
    client_id: str
    #: True when the token carries `openid`, which is what puts `sub` on the profile.
    openid: bool

    def allows(self, scopes: tuple[str, ...]) -> bool:
        return any(self.scope.contains(value) for value in scopes)

    def require(self, scopes: tuple[str, ...]) -> None:
        if not self.allows(scopes):
            raise errors.insufficient_scope(list(scopes))


def oauth_credentials(request: Request) -> TokenCredentials:
    """`Authorization: Bearer <access token>`, verified locally.

    Deliberately strict about the scheme: the profile server has never accepted
    anything but Bearer, and a HAWK header here means the caller has confused a
    session token for an access token — better to say so than to look it up.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise errors.profile_unauthorized("Bearer token not provided")
    token = header[len("bearer ") :].strip()

    keys = request.app.state.signing_keys
    try:
        claims = keys.verify(token)
    except jose.JWTError as exc:
        # A constant reason, not `str(exc)`. Those messages name the `alg` and
        # `kid` the caller sent (`crypto/jose.py`), and this route is
        # unauthenticated: reflecting attacker-chosen bytes back out of it buys
        # a client nothing it can act on — every one of them means "get a new
        # token" — and is a parser detail nobody outside needs.
        raise errors.profile_unauthorized("Invalid token") from exc
    if jose.decode_jwt_header(token).get("typ") != "at+JWT":
        raise errors.profile_unauthorized("Not an access token")
    if claims.get("iss") != request.app.state.config.public_url:
        raise errors.profile_unauthorized("Wrong issuer")

    account = database(request).account(claims.get("sub", ""))
    if account is None:
        # A token can outlive the account it names; the reference answers 401
        # here too, so the client re-authenticates rather than retries.
        raise errors.profile_unauthorized("Unknown account")

    scope = ScopeSet.from_string(claims.get("scope", ""))
    return TokenCredentials(
        account=account,
        scope=scope,
        client_id=claims.get("client_id", ""),
        openid=scope.contains("openid"),
    )


Credentials = Annotated[TokenCredentials, Depends(oauth_credentials)]

router = APIRouter(tags=["profile"])


# DIVERGENCE: metrics-disabled — `metricsEnabled` is always false
#   upstream: reflects the user's telemetry preference, and the settings SPA
#     lets them change it.
#   fxa-lite: hard `false`, here and in `/account/login`, `/account/create` and
#     `/session/status`.
#   why: there is no metrics pipeline to opt into — no Glean, no Sentry, no
#     Amplitude — so the only truthful value is the one that says so. A field
#     Firefox reads cannot simply be omitted.
#   cost: none on the wire. It does mean the value is not a preference a user
#     can set; the answer to "may this server collect telemetry" is no.
@router.get("/profile")
def profile(credentials: Credentials) -> dict[str, Any]:
    """Everything the token's scopes allow, in one document.

    Each field is gated on its own scope, exactly as the reference gates the
    internal `_core_profile` call it assembles this from — a `profile:uid` token
    must not learn the email address on its way past.
    """
    account = credentials.account
    result: dict[str, Any] = {}
    if credentials.allows(UID_SCOPES) or credentials.scope.contains("profile"):
        result["uid"] = account.uid
    if credentials.allows(EMAIL_SCOPES):
        result["email"] = account.email
    if credentials.scope.contains("profile:locale"):
        result["locale"] = account.locale
    if credentials.scope.contains("profile:amr"):
        result["amrValues"] = ["pwd", "email"]
        result["twoFactorAuthentication"] = False
    if credentials.openid:
        result["sub"] = account.uid
    # No avatar store and no display name: saying `avatarDefault` and stopping
    # there lets a client draw its own placeholder.
    result["avatarDefault"] = True
    result["metricsEnabled"] = False
    return result


@router.get("/email")
def email(credentials: Credentials) -> dict[str, str]:
    credentials.require(EMAIL_SCOPES)
    return {"email": credentials.account.email}


@router.get("/uid")
def uid(credentials: Credentials) -> dict[str, str]:
    credentials.require(UID_SCOPES)
    return {"uid": credentials.account.uid}


@router.get("/display_name")
def display_name(credentials: Credentials) -> Response:
    """Always 204: fxa-lite has no display names, and never will have one to set.

    The reference answers 204 for an account that has not set one, so this is
    the same answer a fresh account gets there — no client needs a new branch.
    """
    credentials.require(DISPLAY_NAME_SCOPES)
    return Response(status_code=204)


__all__ = ["router"]
