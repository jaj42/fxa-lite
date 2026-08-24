"""Discovery: the two documents that tell a client where everything lives.

`/.well-known/fxa-client-configuration` is the one that matters.  Point Firefox
at this origin with `identity.fxaccounts.autoconfig.uri` and it reads this
document to find the auth, OAuth, profile and Sync endpoints — which is why the
prefix layout in `app.py` can be whatever we like.

Firefox appends the version segment itself: it takes `auth_server_base_url` and
requests `<base>/v1/...`, and takes `sync_tokenserver_base_url` and requests
`<base>/1.0/sync/1.5`.  So the bases here end *before* those segments, and the
content server upstream goes out of its way to strip a `/v1` suffix for exactly
that reason.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response

from .config import Config

router = APIRouter(tags=["discovery"])

#: A day. The document changes when the deployment does, which is to say never.
CACHE_CONTROL = "public, max-age=86400"


@router.get("/.well-known/fxa-client-configuration")
def fxa_client_configuration(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = CACHE_CONTROL
    config: Config = request.app.state.config
    return {
        # No `/v1`: Firefox adds it.
        "auth_server_base_url": config.public_url,
        "oauth_server_base_url": config.public_url,
        "profile_server_base_url": config.url("/profile"),
        # Firefox appends `/1.0/sync/1.5`.
        "sync_tokenserver_base_url": config.url("/token"),
        # QR pairing needs a channelserver, which is out of scope. Advertising
        # our own origin means a pairing attempt fails at connect time, where
        # the user can see it, rather than being silently pointed at Mozilla's.
        "pairing_server_base_uri": _websocket_url(config.public_url),
    }


@router.get("/.well-known/openid-configuration")
def openid_configuration(request: Request, response: Response) -> dict[str, Any]:
    """OIDC discovery. `issuer` is the origin, and matches the `iss` we sign."""
    response.headers["Cache-Control"] = CACHE_CONTROL
    config: Config = request.app.state.config
    return {
        # The sign-in page (phase 4), not an API route.
        "authorization_endpoint": config.url("/authorization"),
        "introspection_endpoint": config.url("/v1/introspect"),
        "issuer": config.public_url,
        "jwks_uri": config.url("/v1/jwks"),
        # fxa-lite serves the RFC 7009 route at the auth-server-flavoured path,
        # so discovery points there rather than at the oauth-server's `/v1/destroy`.
        "revocation_endpoint": config.url("/v1/oauth/destroy"),
        "token_endpoint": config.url("/v1/oauth/token"),
        "userinfo_endpoint": config.url("/profile/v1/profile"),
        "verify_endpoint": config.url("/v1/verify"),
    }


def _websocket_url(url: str) -> str:
    parts = urlsplit(url)
    return parts._replace(scheme="wss" if parts.scheme == "https" else "ws").geturl()


__all__ = ["router"]
