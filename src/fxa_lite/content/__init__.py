"""The content server: the pages Firefox opens, and the assets they load.

Upstream this is two packages — `fxa-content-server` and the `fxa-settings`
React app — behind their own origin.  Here it is one HTML document, one
stylesheet and three ES modules, served from the same origin as the API so the
page can call `/v1/...` with no CORS and no configuration to keep in sync.

Firefox picks the URLs, not us.  With `identity.fxaccounts.autoconfig.uri`
pointing here it opens **`/`** to sign in (`FxAccountsConfig`'s "email first"
entry point, with the OAuth parameters in the query string), `/settings` to
manage the account, and `/pair` or `/connect_another_device` from the Sync
panel.  Every one of those has to answer with something, so every one of them
is served — `/` included, which is why the auth server's own `/` landing JSON
moved aside in `app.py`.

Which view the document shows is decided in `assets/app.js` from the path; the
server's only job is to hand over the same shell each time, with headers that
suit a page that handles a password:

* `Referrer-Policy: no-referrer` — the query string carries `keys_jwk`,
  `state` and `code_challenge`;
* `Cache-Control: no-store` on the document, so a signed-in page is not left
  in the back/forward cache of a shared machine;
* a CSP with no `unsafe-inline` anywhere, which is why the scripts are
  separate files rather than inline in the shell.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from fastapi import APIRouter, Request, Response
from starlette.exceptions import HTTPException

ASSET_DIR = Path(__file__).parent / "assets"

#: The routes Firefox navigates to by itself. `/authorization` and
#: `/oauth/signin` are the reference's own names for the OAuth sign-in page;
#: `/signin` is what a person types.
PAGE_PATHS = (
    "/",
    "/signin",
    "/oauth/signin",
    "/authorization",
    "/pair",
    "/connect_another_device",
    "/settings",
)

#: `default-src 'none'` and no `unsafe-inline`: everything this page loads is
#: one of our own files, and everything it talks to is this origin.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

_MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


class Asset:
    """One file, read once at import, with the ETag it will be served under."""

    __slots__ = ("body", "etag", "media_type")

    def __init__(self, path: Path) -> None:
        self.body = path.read_bytes()
        self.media_type = _MEDIA_TYPES[path.suffix]
        self.etag = f'"{sha256(self.body).hexdigest()[:32]}"'


def _load(name: str) -> Asset:
    path = ASSET_DIR / name
    # Nothing outside `assets/` is reachable: the names are a fixed table, not
    # anything a request supplies.
    return Asset(path)


SHELL = _load("index.html")
STATIC: dict[str, Asset] = {
    name: _load(name) for name in ("app.js", "api.js", "crypto.js", "webchannel.js", "style.css")
}

router = APIRouter(tags=["content"])


def _shell_response() -> Response:
    return Response(
        content=SHELL.body,
        media_type=SHELL.media_type,
        headers={
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            # An authenticated page on a machine that may be shared.
            "Cache-Control": "no-store",
        },
    )


def page() -> Response:
    """Every navigable content-server route: the same shell each time."""
    return _shell_response()


for _path in PAGE_PATHS:
    # The shell is bytes we built ourselves, so `response_class` stops FastAPI
    # from trying to serialise the return value again.
    router.add_api_route(
        _path, page, methods=["GET"], include_in_schema=False, response_class=Response
    )


@router.get("/settings/{subpath:path}", include_in_schema=False)
def settings_subpage(subpath: str) -> Response:
    """`/settings/clients` and friends, which Firefox links to directly.

    The settings view is the same document; it says what fxa-lite does not do
    rather than 404-ing at someone who followed a link out of the Sync panel.
    """
    return _shell_response()


@router.get("/oauth/success/{client_id}", include_in_schema=False)
def oauth_success(client_id: str) -> Response:
    """The redirect the mobile browsers watch for, registered in `oauth/clients.py`.

    Nothing on the page matters: Firefox for iOS and Fenix read `code` and
    `state` off the URL and close the tab. What matters is that the URL loads
    at all — a registered redirect that 404s strands the flow on an error page.
    """
    return _shell_response()


@router.get("/static/{name}", include_in_schema=False)
def static_asset(name: str, request: Request) -> Response:
    """The page's own assets, revalidated on every load.

    There is no content hash in the filename, so the cache is told to check
    each time; the ETag makes that check a 304 rather than a re-download.
    """
    asset = STATIC.get(name)
    if asset is None:
        # Rendered as the usual FxA envelope by `app.py`'s handler, so even a
        # mistyped asset URL answers in the one format this server speaks.
        raise HTTPException(status_code=404)
    headers = {
        "ETag": asset.etag,
        "Cache-Control": "public, max-age=0, must-revalidate",
        "X-Content-Type-Options": "nosniff",
    }
    if request.headers.get("if-none-match") == asset.etag:
        return Response(status_code=304, headers=headers)
    return Response(content=asset.body, media_type=asset.media_type, headers=headers)


__all__ = ["PAGE_PATHS", "router"]
