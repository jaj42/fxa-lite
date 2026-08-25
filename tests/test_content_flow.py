"""The sign-in flow, driven through the page's own JavaScript.

`content/assets/app.js` decides the WebChannel message sequence, and every rule
that governs it is invisible from the server: the browser is the only thing
that would notice `fxaccounts:oauth_login` arriving before `fxaccounts:login`,
or key material riding along on an OAuth `fxaccounts:login` where it causes
intermittent Sync disconnects.

So these tests put the page in front of a real server — uvicorn on a loopback
port, because node's `fetch` needs a socket where the other suites use an ASGI
transport — and record what the page sends.  The DOM it runs against is the
minimum `app.js` touches (`tests/js/signin_harness.mjs`); this checks the flow,
not the rendering.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ec

from conformance.client import (
    FIREFOX_DESKTOP_CLIENT_ID,
    OLDSYNC_SCOPE,
    b64u,
    generate_relier_keypair,
    get_credentials,
    jwe_decrypt_ecdh_es,
    public_jwk,
)
from fxa_lite import accounts, content
from fxa_lite.app import create_app
from fxa_lite.config import from_dict
from fxa_lite.crypto import jose
from fxa_lite.db import open_database
from fxa_lite.oauth.keys import SigningKeys
from nodejs import require_node

HARNESS = Path(__file__).parent / "js" / "signin_harness.mjs"

EMAIL = "sync-user@example.com"
PASSWORD = "correct horse battery staple"

#: What Firefox answers to `fxaccounts:fxa_status` on a fresh profile.
BROWSER_ENGINES = ["bookmarks", "history", "passwords", "tabs", "creditcards"]


@pytest.fixture(scope="module")
def node() -> str:
    return require_node("the sign-in page cannot be driven")


@pytest.fixture(scope="module")
def relier_key() -> ec.EllipticCurvePrivateKey:
    """The P-256 key Firefox generates and advertises as `keys_jwk`."""
    return generate_relier_keypair()


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """The whole app on a loopback port, with one account already provisioned."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    db = open_database(":memory:")
    accounts.provision(
        db, email=EMAIL, auth_pw=get_credentials(EMAIL, PASSWORD).auth_pw, locale=None
    )
    key = jose.generate_signing_key()
    jwk = jose.private_key_to_jwk(key)
    app = create_app(
        from_dict({"public_url": base_url}),
        db=db,
        signing_keys=SigningKeys(
            private=key,
            kid=jwk["kid"],
            verifiers={jwk["kid"]: key.public_key()},
            jwks={"keys": [jose.public_jwk(jwk)]},
        ),
    )
    uvicorn_server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=uvicorn_server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not uvicorn_server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield base_url
    finally:
        uvicorn_server.should_exit = True
        thread.join(timeout=10)
        db.close()


def run_page(node: str, server: str, job: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        [node, str(HARNESS), str(content.ASSET_DIR), server],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        pytest.fail(f"the sign-in page failed to run:\n{completed.stderr}")
    result = json.loads(completed.stdout)
    assert "error" not in result, result["error"]
    return result


def oauth_query(relier_key: ec.EllipticCurvePrivateKey, **overrides: str) -> str:
    """The query string Firefox Desktop opens the sign-in page with."""
    params = {
        "client_id": FIREFOX_DESKTOP_CLIENT_ID,
        "context": "oauth_webchannel_v1",
        "service": "sync",
        "action": "email",
        "response_type": "code",
        "access_type": "offline",
        "scope": f"{OLDSYNC_SCOPE} profile",
        "state": "state-from-the-browser",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
        "keys_jwk": b64u(json.dumps(public_jwk(relier_key)).encode()),
        **overrides,
    }
    return "?" + urlencode(params)


def browser(**replies: Any) -> dict[str, Any]:
    return {
        "replies": {
            "fxaccounts:fxa_status": {
                "capabilities": {"engines": BROWSER_ENGINES, "multiService": True},
                "clientId": FIREFOX_DESKTOP_CLIENT_ID,
            },
            "fxaccounts:can_link_account": {"ok": True},
            **replies,
        }
    }


def messages_of(result: dict[str, Any], command: str) -> list[dict[str, Any]]:
    return [message["data"] for message in result["messages"] if message["command"] == command]


# --------------------------------------------------------------------------
# The OAuth flow — what a current Firefox Desktop does.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def oauth_result(
    node: str, server: str, relier_key: ec.EllipticCurvePrivateKey
) -> dict[str, Any]:
    return run_page(
        node,
        server,
        {
            "path": "/",
            "query": oauth_query(relier_key),
            "email": EMAIL,
            "password": PASSWORD,
            "browser": browser(),
        },
    )


def test_the_flow_asks_the_browser_before_it_creates_a_session(
    oauth_result: dict[str, Any],
) -> None:
    """`fxa_status` first, then `can_link_account`, and only then a password.

    Asking to link before signing in is upstream's order and the useful one: a
    user who cancels the browser's dialog leaves no session token behind.
    """
    commands = [message["command"] for message in oauth_result["messages"]]
    assert commands[0] == "fxaccounts:fxa_status"
    assert commands[1] == "fxaccounts:can_link_account"
    assert messages_of(oauth_result, "fxaccounts:can_link_account")[0]["email"] == EMAIL


def test_login_precedes_oauth_login(oauth_result: dict[str, Any]) -> None:
    """The ordering rule from `Signin/utils.ts`: "This _must_ be sent before"."""
    commands = [message["command"] for message in oauth_result["messages"]]
    assert commands.index("fxaccounts:login") < commands.index("fxaccounts:oauth_login")


def test_oauth_login_carries_no_key_material(oauth_result: dict[str, Any]) -> None:
    """The other rule: no `keyFetchToken`/`unwrapBKey` on an OAuth flow.

    The scoped keys already travel inside `keys_jwe`; sending them a second
    time is what causes the intermittent Sync disconnects the reference warns
    about. The session token is still there, because the browser needs it.
    """
    login = messages_of(oauth_result, "fxaccounts:login")[0]
    assert "keyFetchToken" not in login
    assert "unwrapBKey" not in login
    assert login["email"] == EMAIL
    assert login["verified"] is True
    assert login["verifiedCanLinkAccount"] is True
    assert len(login["sessionToken"]) == 64


def test_the_page_offers_back_the_engines_the_browser_named(
    oauth_result: dict[str, Any],
) -> None:
    """There is no "choose what to sync" screen, so nothing is ever declined."""
    login = messages_of(oauth_result, "fxaccounts:login")[0]
    assert login["services"] == {
        "sync": {"offeredEngines": BROWSER_ENGINES, "declinedEngines": []}
    }
    oauth_login = messages_of(oauth_result, "fxaccounts:oauth_login")[0]
    assert oauth_login["offeredSyncEngines"] == BROWSER_ENGINES
    assert oauth_login["declinedSyncEngines"] == []


def test_oauth_login_returns_the_browsers_own_state_and_the_sentinel(
    oauth_result: dict[str, Any],
) -> None:
    oauth_login = messages_of(oauth_result, "fxaccounts:oauth_login")[0]
    assert oauth_login["action"] == "signin"
    assert oauth_login["state"] == "state-from-the-browser"
    # The bare sentinel, as `sendOAuthResultToRelier` sends it: not a location,
    # and not the code-bearing URL the server echoed back.
    assert oauth_login["redirect"] == "urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel"
    assert len(oauth_login["code"]) == 64
    assert OLDSYNC_SCOPE in oauth_login["scope"]
    # A WebChannel flow is completed by the browser, never by navigating.
    assert "code=" not in oauth_result["href"]


def test_the_code_redeems_to_the_sync_key_the_page_sealed(
    oauth_result: dict[str, Any], server: str, relier_key: ec.EllipticCurvePrivateKey
) -> None:
    """The end of the phase-3 flow, but with the page doing the client's half.

    Firefox takes the code from `fxaccounts:oauth_login`, exchanges it, and
    opens `keys_jwe` with the private half of the `keys_jwk` it advertised.
    That the oldsync key comes back out is the whole point of the page.
    """
    oauth_login = messages_of(oauth_result, "fxaccounts:oauth_login")[0]
    token = httpx.post(
        f"{server}/v1/oauth/token",
        json={
            "client_id": FIREFOX_DESKTOP_CLIENT_ID,
            "code": oauth_login["code"],
            # The verifier behind the fixed challenge in `oauth_query`.
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        },
        timeout=30,
    ).json()
    assert "access_token" in token, token

    keys = json.loads(jwe_decrypt_ecdh_es(token["keys_jwe"], relier_key))
    oldsync = keys[OLDSYNC_SCOPE]
    assert oldsync["kty"] == "oct"
    # 64 bytes, base64url, unpadded: the legacy Sync derivation.
    assert len(oldsync["k"]) == 86


# --------------------------------------------------------------------------
# The older Sync flow, and the pages that are not sign-in.
# --------------------------------------------------------------------------


def test_the_legacy_sync_flow_hands_over_the_key_fetch_token(node: str, server: str) -> None:
    """`fx_desktop_v3` has no OAuth: the browser fetches the keys itself.

    Here `keyFetchToken` and `unwrapBKey` are exactly what the message is for —
    the mirror image of the OAuth rule, and the reason the page cannot simply
    always send them or always leave them out.
    """
    result = run_page(
        node,
        server,
        {
            "path": "/signin",
            "query": "?context=fx_desktop_v3&service=sync&action=email",
            "email": EMAIL,
            "password": PASSWORD,
            "browser": browser(),
        },
    )
    commands = [message["command"] for message in result["messages"]]
    assert "fxaccounts:oauth_login" not in commands

    login = messages_of(result, "fxaccounts:login")[0]
    assert len(login["keyFetchToken"]) == 64
    assert len(login["unwrapBKey"]) == 64
    assert login["services"] == {
        "sync": {"offeredEngines": BROWSER_ENGINES, "declinedEngines": []}
    }


def test_a_cancelled_link_stops_before_any_password_is_sent(node: str, server: str) -> None:
    result = run_page(
        node,
        server,
        {
            "path": "/",
            "query": "?context=fx_desktop_v3&service=sync",
            "email": EMAIL,
            "password": PASSWORD,
            "browser": browser(**{"fxaccounts:can_link_account": {"ok": False}}),
        },
    )
    assert messages_of(result, "fxaccounts:login") == []
    assert "cancelled in the browser" in result["rendered"]


def test_a_wrong_password_is_reported_and_nothing_is_sent(node: str, server: str) -> None:
    result = run_page(
        node,
        server,
        {
            "path": "/",
            "query": "?context=fx_desktop_v3&service=sync",
            "email": EMAIL,
            "password": "not the password",
            "browser": browser(),
        },
    )
    assert messages_of(result, "fxaccounts:login") == []
    # The server's own message, from the FxA error envelope.
    assert "Incorrect password" in result["rendered"]


def test_the_pairing_page_says_so_rather_than_hanging(node: str, server: str) -> None:
    """Firefox links to /pair from the Sync panel; a 404 there is a dead end."""
    result = run_page(node, server, {"path": "/pair", "browser": browser()})
    assert result["messages"] == []
    assert "Not available" in result["rendered"]


def test_the_settings_page_reports_the_connected_account(node: str, server: str) -> None:
    result = run_page(
        node,
        server,
        {
            "path": "/settings",
            "query": "?context=fx_desktop_v3&service=sync",
            "browser": {
                "replies": {
                    "fxaccounts:fxa_status": {
                        "capabilities": {"engines": BROWSER_ENGINES},
                        "signedInUser": {"email": EMAIL, "uid": "a" * 32, "verified": True},
                    }
                }
            },
        },
    )
    assert EMAIL in result["rendered"]
    assert "command line" in result["rendered"]
