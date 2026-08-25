"""The content server: the pages Firefox opens and the assets they pull.

There is no browser here, so what these tests can check is the contract the
page depends on — that every URL Firefox navigates to answers with the shell,
that the shell's own assets are served and cacheable, and that the headers a
password page needs are actually set.  The JavaScript itself is exercised under
node in `test_content_crypto.py`.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from fxa_lite import content

ASSET_NAMES = sorted(content.STATIC)


@pytest.mark.parametrize("path", content.PAGE_PATHS)
async def test_every_page_route_serves_the_shell(http: httpx.AsyncClient, path: str) -> None:
    response = await http.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.content == content.SHELL.body


async def test_the_root_is_the_sign_in_page(http: httpx.AsyncClient) -> None:
    """`identity.fxaccounts.autoconfig.uri` sends Firefox to `/` to sign in.

    Upstream the auth server answers `/` with its version document, but that is
    a different origin there; here the sign-in page wins and the version moved
    to `/__version__` alone.
    """
    assert (await http.get("/")).headers["content-type"].startswith("text/html")
    assert (await http.get("/__version__")).json()["version"]


async def test_settings_subpaths_are_served(http: httpx.AsyncClient) -> None:
    # `promiseManageDevicesURI` links straight to /settings/clients.
    response = await http.get("/settings/clients")
    assert response.status_code == 200
    assert response.content == content.SHELL.body


async def test_the_mobile_oauth_redirect_lands_somewhere(http: httpx.AsyncClient) -> None:
    """`<public_url>/oauth/success/<client_id>` is a registered redirect_uri.

    Fenix and Firefox for iOS read `code` and `state` off this URL. A 404 here
    would strand a redirect flow on an error page instead of completing it.
    """
    response = await http.get("/oauth/success/5882386c6d801776?code=abc&state=xyz")
    assert response.status_code == 200
    assert response.content == content.SHELL.body


async def test_the_paths_the_rust_client_builds_itself_are_all_served() -> None:
    """`fxa-client` joins some content paths from a literal, not from discovery.

    `internal/config.rs` has one method per page it may open, and four of them
    are reachable from a signed-in phone: `connect_another_device`, `pair`,
    `pair/supp` and `oauth/force_auth` — the last being where
    `begin_oauth_flow` sends a re-authentication, in place of the
    `authorization_endpoint` that discovery does name. Discovery cannot fix a
    404 on any of them, so they are pinned here by the name upstream uses.
    """
    for path in ("/connect_another_device", "/pair", "/pair/supp", "/oauth/force_auth"):
        assert path in content.PAGE_PATHS


async def test_the_shell_carries_the_headers_a_password_page_needs(
    http: httpx.AsyncClient,
) -> None:
    headers = (await http.get("/signin")).headers
    # The query string holds keys_jwk, state and code_challenge.
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert headers["x-frame-options"] == "DENY"
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp


@pytest.mark.parametrize("name", ASSET_NAMES)
async def test_assets_are_served_and_revalidated(http: httpx.AsyncClient, name: str) -> None:
    response = await http.get(f"/static/{name}")
    assert response.status_code == 200
    assert response.content == content.STATIC[name].body
    assert response.headers["cache-control"] == "public, max-age=0, must-revalidate"

    cached = await http.get(f"/static/{name}", headers={"if-none-match": response.headers["etag"]})
    assert cached.status_code == 304
    assert cached.content == b""


async def test_an_unknown_asset_answers_in_the_fxa_envelope(http: httpx.AsyncClient) -> None:
    response = await http.get("/static/../db.py")
    assert response.status_code == 404
    # Not FastAPI's `{"detail": ...}`: every response from this server carries
    # an errno, including the ones that are nobody's fault.
    assert response.json()["errno"] == 116


async def test_an_unknown_page_is_still_a_404(http: httpx.AsyncClient) -> None:
    # The content routes are a fixed list, not a catch-all: a typo'd API path
    # must not be answered with a sign-in page.
    response = await http.get("/v1/account/nope")
    assert response.status_code == 404
    assert response.json()["errno"] == 116


def test_the_shell_loads_only_its_own_assets() -> None:
    """`script-src 'self'` means a CDN reference is a blank page, not a slow one."""
    shell = content.SHELL.body.decode()
    assert '<script type="module" src="/static/app.js">' in shell
    assert '<link rel="stylesheet" href="/static/style.css" />' in shell
    for source in [shell, *(asset.body.decode() for asset in content.STATIC.values())]:
        assert "//fonts." not in source
        assert "https://" not in source.replace("https://identity.", "")


def test_the_page_never_assigns_markup() -> None:
    """The one invariant that keeps URL parameters out of the DOM as HTML.

    `app.js` puts the client id and the account's email on the page. It builds
    every node with `createElement` and `createTextNode`, so there is no path
    from a query parameter to parsed markup — and this test is what keeps it
    that way.
    """
    for name in ASSET_NAMES:
        if name.endswith(".js"):
            source = content.STATIC[name].body.decode()
            assert "innerHTML" not in source
            assert "outerHTML" not in source
            assert "insertAdjacentHTML" not in source


def test_every_asset_on_disk_is_served() -> None:
    """A file added to `assets/` but not to the table is a 404 nobody notices."""
    on_disk = {path.name for path in Path(content.ASSET_DIR).iterdir() if path.is_file()}
    assert on_disk == {*ASSET_NAMES, "index.html"}


async def test_the_favicon_is_served(http) -> None:
    """A browser asks for `/favicon.ico` without being told to; the shell names
    its icon in a `<link>`, and the well-known path answers too rather than
    writing a 404 to the log on every navigation that misses the link."""
    assert '<link rel="icon" href="/static/icon.svg"' in content.SHELL.body.decode()

    response = await http.get("/favicon.ico")
    assert response.status_code == 200
    # The extension is a convention; the Content-Type is the declaration.
    assert response.headers["content-type"] == "image/svg+xml"
    assert response.content == content.STATIC["icon.svg"].body
