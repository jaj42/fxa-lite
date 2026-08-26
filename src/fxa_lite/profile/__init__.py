# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The profile server, mounted at `/profile/v1`.

`fxa-profile-server` is a separate process upstream that answers every request
by calling the OAuth server's `/v1/verify` and then the auth server's
`/v1/account/profile` over HTTP.  Here both are local: the access token is
verified against the signing key in memory, and the account is read from the
same SQLite file.

What is missing is missing on purpose.  fxa-lite stores no avatars and no
display names, so `displayName` is simply absent rather than reported as an
empty string — a client that sees no `displayName` falls back to the email,
which is the right outcome; one that sees `""` renders a blank.

`avatar` is the exception, and it is not optional.  The reference always
answers with a URL — an uploaded image, or the monogram route below — and
Firefox for Android parses the document into a Rust struct whose `avatar` field
is a plain `String` (`application-services`,
`components/fxa-client/src/internal/http_client.rs`, `ProfileResponse`).
Leaving the key out makes that parse fail, the phone never learns its own
address, and its menu offers to sign in to an account it is already syncing
with.  So the monogram is served rather than omitted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from .. import errors
from ..auth.credentials import database
from ..content import ASSET_CONTENT_SECURITY_POLICY
from ..crypto import jose
from ..db import Account
from ..oauth.scopes import ScopeSet

#: `openid`'s counterpart to `profile:email`; both grant the address.
EMAIL_SCOPES = ("profile:email", "email")
UID_SCOPES = ("profile:uid",)
DISPLAY_NAME_SCOPES = ("profile:display_name",)
AVATAR_SCOPES = ("profile:avatar",)

#: The monogram a token that may see the avatar but not the address gets.
#: The route renders anything that is not one alphanumeric character as `?`,
#: which is upstream's own rule, so the name is a description and not a token.
DEFAULT_MONOGRAM = "default"


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
def profile(credentials: Credentials, request: Request) -> dict[str, Any]:
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
    if credentials.allows(AVATAR_SCOPES):
        # Both keys or neither, which is what the reference's own assembly
        # produces: they come from one internal `/v1/avatar` call, and a
        # `profile:avatar`-less token gets a 403 that drops the pair.
        result["avatar"] = _avatar_url(request, account, credentials)
        result["avatarDefault"] = True
    result["metricsEnabled"] = False
    return result


# DIVERGENCE: avatar-is-always-a-monogram — no pictures, and `avatarDefault` is never false
#   upstream: stores uploaded avatars, serves them from an image service, and
#     falls back to a generated monogram for an account that has not set one.
#     `/v1/avatar` and its upload and delete siblings are part of the API.
#   fxa-lite: has no image store and serves no upload route, so the answer is
#     always the monogram and `avatarDefault` is always `true`.
#   why: an avatar is a file store, a resizer and a cache — the three things
#     this project exists to not run — and none of them are protocol. What *is*
#     protocol is that the key is there: the Rust client every Firefox for
#     Android build embeds parses the profile document into a struct whose
#     `avatar` is a plain `String`, so omitting it fails the parse, and a phone
#     with no profile shows a sign-in prompt for the account it is syncing with.
#   cost: a household cannot set a profile picture, on any client. The monogram
#     is drawn from the address, so the initial in a browser's account menu is
#     the right one; there is nothing else to lose.
def _avatar_url(request: Request, account: Account, credentials: TokenCredentials) -> str:
    """The monogram URL for this account: never an upload, always this origin.

    Upstream builds the same URL for an account that has not uploaded a picture
    (`routes/profile.js:nextAvatar`), from the first alphanumeric character of
    the display name or the address.  We have no display names, so it is the
    address — and only for a token that is allowed to see the address, because
    an initial is a fact about it.  Upstream declines to guess for the same
    reason: "a missing email means scope hid it, so no initial is knowable yet".
    """
    monogram = DEFAULT_MONOGRAM
    if credentials.allows(EMAIL_SCOPES):
        initial = next((c for c in account.email if c.isascii() and c.isalnum()), "")
        monogram = initial or DEFAULT_MONOGRAM
    return request.app.state.config.url(f"/profile/v1/avatar/{monogram}")


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


#: One alphanumeric character in a circle. Transcribed from
#: `fxa-profile-server/lib/routes/avatar/default.js`, without the base64 WOFF it
#: embeds: shipping a font to guarantee one glyph is a trade for a service that
#: renders millions of these, and a generic family renders the same letter here.
MONOGRAM_SVG = """<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <mask id="monogram">
    <rect x="0" y="0" width="100%" height="100%" fill="white"/>
    <text x="50%" y="50%" dominant-baseline="central" text-anchor="middle"
          fill="black" font-family="sans-serif" font-weight="bold"
          font-size="64">{monogram}</text>
  </mask>
  <circle cx="50" cy="50" r="50" fill="#B2B2B4" fill-opacity="0.7" mask="url(#monogram)"/>
</svg>
"""


@router.get("/avatar/{monogram}", include_in_schema=False)
def avatar(monogram: str) -> Response:
    """The picture `/profile` points at, for an account that has no picture.

    Unauthenticated on purpose, as upstream's is: this URL is loaded by an
    `<img>` in a browser chrome that has no access token to spend on it, and it
    discloses one character that the caller was already given in the profile
    document it came from.

    Anything that is not a single ASCII alphanumeric renders `?` — upstream's
    rule, which is what makes `DEFAULT_MONOGRAM` a name and not a special case.
    """
    letter = (
        monogram.upper()
        if len(monogram) == 1 and monogram.isascii() and monogram.isalnum()
        else "?"
    )
    return Response(
        content=MONOGRAM_SVG.format(monogram=letter),
        media_type="image/svg+xml",
        headers={
            # A letter in a circle is the same letter next week.
            "Cache-Control": "public, max-age=604800, immutable",
            # An SVG served from this origin is a document that could carry
            # script; `content/__init__.py` closes that off the same way.
            "Content-Security-Policy": ASSET_CONTENT_SECURITY_POLICY,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


__all__ = ["router"]
