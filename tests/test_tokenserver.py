# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`GET /token/1.0/sync/1.5` — the hand-off from OAuth to Sync storage.

Two things are being tested here and they are quite different in kind.

The first is the credential itself: whether the token fxa-lite mints is one a
real syncstorage node would accept. `tests/conformance/client.py` implements
the *reader* — tokenlib's verification half, written out from
`syncstorage-rs/tokenserver-auth/src/token/native.rs` — so the assertions below
are made by an independent implementation rather than by fxa-lite agreeing
with itself.

The second is the consistency rules around `generation`, `keysChangedAt` and
the client state. Those exist to catch a client presenting stale key material,
and getting them wrong is invisible until the day someone's Sync history turns
into undecryptable noise. Each rule gets its own test with the credential
hand-built, because a real client cannot produce most of these situations.
"""

import base64
import hashlib
import json
import time

import pytest

from conformance.client import (
    FIREFOX_DESKTOP_CLIENT_ID,
    OLDSYNC_SCOPE,
    AuthClient,
    TokenserverClient,
    TokenserverError,
    b64u,
    derive_sync_key,
    parse_sync_token,
    sync_key_id,
)
from conftest import EMAIL, PASSWORD, PUBLIC_URL
from fxa_lite.crypto import jose

TOKEN_PATH = "/token/1.0/sync/1.5"


async def _sync_grant(client: AuthClient):
    """Sign in the way Firefox does, all the way to a Sync key and an access token."""
    await client.sign_up(EMAIL, PASSWORD)
    return await client.sync_sign_in(EMAIL, PASSWORD)


def _key_id(grant) -> str:
    return sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])


# --------------------------------------------------------------------------
# The happy path.
# --------------------------------------------------------------------------


async def test_sync_flow_reaches_a_storage_credential(
    bearer_client: AuthClient, tokenserver: TokenserverClient, tokenserver_secret: str
) -> None:
    """Password to storage node, and the token verifies against the shared secret."""
    grant = await _sync_grant(bearer_client)
    result = await tokenserver.token(grant.access_token, _key_id(grant))

    assert result["hashalg"] == "sha256"
    assert result["api_endpoint"] == f"{PUBLIC_URL}/storage/1.5/{result['uid']}"
    assert result["duration"] == 3600

    claims = parse_sync_token(result["id"], tokenserver_secret)
    assert claims["uid"] == result["uid"]
    assert claims["fxa_uid"] == grant.account["uid"]
    assert claims["node"] == f"{PUBLIC_URL}/storage"
    assert claims["hashed_fxa_uid"] == result["hashed_fxa_uid"]
    # The HAWK key is bound to the token text and its salt, so re-deriving it
    # is the whole of what a storage node does before checking a signature.
    assert derive_sync_key(result["id"], claims["salt"], tokenserver_secret) == result["key"]


async def test_token_expires_within_the_configured_duration(
    bearer_client: AuthClient, tokenserver: TokenserverClient, tokenserver_secret: str
) -> None:
    grant = await _sync_grant(bearer_client)
    result = await tokenserver.token(grant.access_token, _key_id(grant))
    claims = parse_sync_token(result["id"], tokenserver_secret)
    assert time.time() < claims["expires"] <= time.time() + result["duration"] + 1


async def test_fxa_kid_names_the_same_key_the_client_derived(
    bearer_client: AuthClient, tokenserver: TokenserverClient, tokenserver_secret: str
) -> None:
    """`fxa_kid` is the storage tier's copy of the `kid` in `keys_jwe`.

    Storage stores it beside every collection; if it disagreed with what the
    client derived from `kB`, the client would be handed back records it cannot
    decrypt and would silently wipe them.
    """
    grant = await _sync_grant(bearer_client)
    result = await tokenserver.token(grant.access_token, _key_id(grant))
    claims = parse_sync_token(result["id"], tokenserver_secret)

    keys_changed_at, _, client_state = _key_id(grant).partition("-")
    assert claims["fxa_kid"] == f"{int(keys_changed_at):013d}-{client_state}"
    assert client_state == b64u(hashlib.sha256(grant.keys["kB"]).digest()[:16])


async def test_salt_is_fresh_per_token(
    bearer_client: AuthClient, tokenserver: TokenserverClient, tokenserver_secret: str
) -> None:
    """Two tokens for the same user in the same second must not share a HAWK key."""
    grant = await _sync_grant(bearer_client)
    first = await tokenserver.token(grant.access_token, _key_id(grant))
    second = await tokenserver.token(grant.access_token, _key_id(grant))

    assert first["uid"] == second["uid"]
    assert first["id"] != second["id"]
    assert first["key"] != second["key"]
    assert (
        parse_sync_token(first["id"], tokenserver_secret)["salt"]
        != parse_sync_token(second["id"], tokenserver_secret)["salt"]
    )


async def test_uid_is_stable_across_requests(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    """Signing in again must not move the account's storage."""
    grant = await _sync_grant(bearer_client)
    first = await tokenserver.token(grant.access_token, _key_id(grant))
    again = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    second = await tokenserver.token(again.access_token, _key_id(again))
    assert first["uid"] == second["uid"]


async def test_a_refreshed_access_token_still_works(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    """The steady state: Firefox spends a refresh token, not a fresh sign-in.

    A refreshed grant carries no `auth_at`, but it must still carry
    `fxa-generation` — without it the tokenserver would read every refreshed
    token as coming from a client too old to report one.
    """
    grant = await _sync_grant(bearer_client)
    first = await tokenserver.token(grant.access_token, _key_id(grant))

    refreshed = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        grant_type="refresh_token",
        refresh_token=grant.token["refresh_token"],
    )
    second = await tokenserver.token(refreshed["access_token"], _key_id(grant))
    assert second["uid"] == first["uid"]


async def test_two_accounts_get_different_uids(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    first = await _sync_grant(bearer_client)
    await bearer_client.sign_up("second@example.com", PASSWORD)
    second = await bearer_client.sync_sign_in("second@example.com", PASSWORD)

    mine = await tokenserver.token(first.access_token, _key_id(first))
    theirs = await tokenserver.token(second.access_token, _key_id(second))
    assert mine["uid"] != theirs["uid"]


async def test_response_carries_the_headers_sync_expects(
    bearer_client: AuthClient, http
) -> None:
    grant = await _sync_grant(bearer_client)
    response = await http.get(
        TOKEN_PATH,
        headers={"Authorization": f"Bearer {grant.access_token}", "X-KeyID": _key_id(grant)},
    )
    assert response.status_code == 200
    # Firefox reads X-Timestamp to measure its own clock skew before signing
    # HAWK requests against the node.
    assert abs(int(response.headers["X-Timestamp"]) - time.time()) < 5
    assert response.headers["X-Content-Type-Options"] == "nosniff"


# --------------------------------------------------------------------------
# `duration`, and the X-Client-State header.
# --------------------------------------------------------------------------


async def test_duration_may_be_shortened_but_not_extended(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    grant = await _sync_grant(bearer_client)
    shorter = await tokenserver.token(grant.access_token, _key_id(grant), duration=60)
    assert shorter["duration"] == 60
    longer = await tokenserver.token(grant.access_token, _key_id(grant), duration=99999)
    assert longer["duration"] == 3600


async def test_unparseable_duration_falls_back_rather_than_failing(
    bearer_client: AuthClient, http
) -> None:
    """Upstream is explicit that a bad `duration` must never fail a request."""
    grant = await _sync_grant(bearer_client)
    response = await http.get(
        TOKEN_PATH,
        params={"duration": "soon"},
        headers={"Authorization": f"Bearer {grant.access_token}", "X-KeyID": _key_id(grant)},
    )
    assert response.status_code == 200
    assert response.json()["duration"] == 3600


async def test_matching_client_state_header_is_accepted(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    grant = await _sync_grant(bearer_client)
    key_id = _key_id(grant)
    hex_state = hashlib.sha256(grant.keys["kB"]).digest()[:16].hex()
    result = await tokenserver.token(grant.access_token, key_id, client_state=hex_state)
    assert result["uid"]


async def test_mismatched_client_state_header_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    """The two headers are two spellings of the same 16 bytes; disagreeing is a bug."""
    grant = await _sync_grant(bearer_client)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, _key_id(grant), client_state="00" * 16)
    assert caught.value.status == "invalid-client-state"
    assert caught.value.status_code == 401


async def test_malformed_client_state_header_is_a_400(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    grant = await _sync_grant(bearer_client)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, _key_id(grant), client_state="not hex!")
    assert caught.value.status_code == 400
    assert caught.value.name == "X-Client-State"


# --------------------------------------------------------------------------
# Rejecting the token.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Hawk id=\"deadbeef\"", "Bearer not.a.jwt", "Basic dXNlcjpwYXNz"],
)
async def test_unusable_authorization_headers_are_rejected(
    bearer_client: AuthClient, http, header: str | None
) -> None:
    grant = await _sync_grant(bearer_client)
    headers = {"X-KeyID": _key_id(grant)}
    if header is not None:
        headers["Authorization"] = header
    response = await http.get(TOKEN_PATH, headers=headers)
    assert response.status_code == 401
    assert response.json()["status"] == "invalid-credentials"


async def test_a_token_without_the_sync_scope_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    """The scope is what says this token may be spent here at all."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, scope="profile", service=None)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, f"{int(time.time() * 1000)}-{b64u(b'x' * 16)}")
    assert caught.value.status == "invalid-credentials"


async def test_a_token_signed_by_someone_else_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient
) -> None:
    grant = await _sync_grant(bearer_client)
    claims = json.loads(base64.urlsafe_b64decode(grant.access_token.split(".")[1] + "=="))
    forged = jose.sign_jwt(claims, jose.generate_signing_key(), kid="whoever", typ="at+JWT")
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(forged, _key_id(grant))
    assert caught.value.status == "invalid-credentials"


async def test_an_expired_token_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    grant = await _sync_grant(bearer_client)
    claims = json.loads(base64.urlsafe_b64decode(grant.access_token.split(".")[1] + "=="))
    claims["exp"] = int(time.time()) - 1
    stale = app.state.signing_keys.sign(claims, typ="at+JWT")
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(stale, _key_id(grant))
    assert caught.value.status == "invalid-credentials"


async def test_a_token_for_another_audience_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """fxa-lite checks `aud` where upstream skips it — see `_verified_access_token`."""
    grant = await _sync_grant(bearer_client)
    claims = json.loads(base64.urlsafe_b64decode(grant.access_token.split(".")[1] + "=="))
    claims["aud"] = "https://someone-elses-tokenserver.example"
    elsewhere = app.state.signing_keys.sign(claims, typ="at+JWT")
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(elsewhere, _key_id(grant))
    assert caught.value.status == "invalid-credentials"


async def test_an_id_token_is_not_an_access_token(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    grant = await _sync_grant(bearer_client)
    claims = json.loads(base64.urlsafe_b64decode(grant.access_token.split(".")[1] + "=="))
    not_an_access_token = app.state.signing_keys.sign(claims)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(not_an_access_token, _key_id(grant))
    assert caught.value.status == "invalid-credentials"


async def test_a_token_outliving_its_account_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, db
) -> None:
    grant = await _sync_grant(bearer_client)
    db.delete_account(grant.account["uid"])
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, _key_id(grant))
    assert caught.value.status == "invalid-credentials"


# --------------------------------------------------------------------------
# X-KeyID.
# --------------------------------------------------------------------------


async def test_a_missing_key_id_says_so(
    bearer_client: AuthClient, http
) -> None:
    grant = await _sync_grant(bearer_client)
    response = await http.get(
        TOKEN_PATH, headers={"Authorization": f"Bearer {grant.access_token}"}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["status"] == "invalid-key-id"
    assert body["errors"][0]["description"] == "Missing X-KeyID header"


@pytest.mark.parametrize("key_id", ["nodash", "notanumber-abc", "1234-!!!!"])
async def test_malformed_key_ids_are_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, key_id: str
) -> None:
    grant = await _sync_grant(bearer_client)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, key_id)
    assert caught.value.status_code == 401


# --------------------------------------------------------------------------
# The consistency rules. These are hand-built: a real client cannot get here.
# --------------------------------------------------------------------------


async def _minted(app, grant, *, generation=None, keys_changed_at=None, client_state=None):
    """Re-sign the grant's own claims with the fields a rule turns on."""
    claims = json.loads(base64.urlsafe_b64decode(grant.access_token.split(".")[1] + "=="))
    if generation is not None:
        claims["fxa-generation"] = generation
    token = app.state.signing_keys.sign(claims, typ="at+JWT")
    stored_kca, _, stored_state = _key_id(grant).partition("-")
    timestamp = int(stored_kca) if keys_changed_at is None else keys_changed_at
    state = stored_state if client_state is None else client_state
    return token, f"{timestamp}-{state}"


async def test_a_new_client_state_gets_a_new_uid(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """A key rotation must not hand the new key the old key's records."""
    grant = await _sync_grant(bearer_client)
    first = await tokenserver.token(grant.access_token, _key_id(grant))

    rotated_at = int(time.time() * 1000) + 1000
    token, key_id = await _minted(
        app,
        grant,
        generation=rotated_at,
        keys_changed_at=rotated_at,
        client_state=b64u(b"a-different-key!"),
    )
    second = await tokenserver.token(token, key_id)
    assert second["uid"] != first["uid"]


async def test_a_retired_client_state_can_never_come_back(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """Returning to an old key would write records under a fingerprint we retired."""
    grant = await _sync_grant(bearer_client)
    original_key_id = _key_id(grant)
    await tokenserver.token(grant.access_token, original_key_id)

    rotated_at = int(time.time() * 1000) + 1000
    token, key_id = await _minted(
        app,
        grant,
        generation=rotated_at,
        keys_changed_at=rotated_at,
        client_state=b64u(b"a-different-key!"),
    )
    await tokenserver.token(token, key_id)

    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, original_key_id)
    assert caught.value.status == "invalid-client-state"


async def test_a_new_client_state_without_a_generation_change_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(app, grant, client_state=b64u(b"a-different-key!"))
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-client-state"


async def test_a_new_client_state_without_a_keys_changed_at_change_is_rejected(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(
        app,
        grant,
        generation=int(time.time() * 1000) + 1000,
        client_state=b64u(b"a-different-key!"),
    )
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-client-state"


async def test_generation_may_not_move_backwards(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """A stale token, replayed after a password change, must not be honoured."""
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(app, grant, generation=1)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-generation"


async def test_keys_changed_at_may_not_move_backwards(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(app, grant, keys_changed_at=1)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-keysChangedAt"


async def test_keys_changed_at_may_not_outrun_generation(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """A key change is an authentication change, so it cannot be the newer of the two."""
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    later = int(time.time() * 1000) + 10_000
    token, key_id = await _minted(app, grant, generation=later - 1, keys_changed_at=later)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-keysChangedAt"


async def test_a_client_may_not_stop_reporting_keys_changed_at(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app
) -> None:
    """Once seen, it is required: a stored value read as 0 makes any key look current."""
    grant = await _sync_grant(bearer_client)
    await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(app, grant, keys_changed_at=0)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(token, key_id)
    assert caught.value.status == "invalid-keysChangedAt"


async def test_generation_moving_forward_is_accepted(
    bearer_client: AuthClient, tokenserver: TokenserverClient, app, db
) -> None:
    """A password change raises `generation` alone; the uid and the key stay put."""
    grant = await _sync_grant(bearer_client)
    first = await tokenserver.token(grant.access_token, _key_id(grant))

    token, key_id = await _minted(app, grant, generation=int(time.time() * 1000) + 5000)
    second = await tokenserver.token(token, key_id)
    assert second["uid"] == first["uid"]
    assert db.sync_users(grant.account["uid"])[0].generation > 0


# --------------------------------------------------------------------------
# Routing.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "name"),
    [("/1.0/notsync/1.5", "application"), ("/1.0/sync/1.0", "1.0")],
)
async def test_unsupported_application_or_version_is_a_404(
    bearer_client: AuthClient, tokenserver: TokenserverClient, path: str, name: str
) -> None:
    grant = await _sync_grant(bearer_client)
    with pytest.raises(TokenserverError) as caught:
        await tokenserver.token(grant.access_token, _key_id(grant), path=path)
    assert caught.value.status_code == 404
    assert caught.value.location == "url"
    assert caught.value.name == name


async def test_a_stray_path_below_token_answers_in_the_tokenserver_envelope(http) -> None:
    """Firefox parses this response with the tokenserver's parser, not the API's."""
    response = await http.get("/token/nonsense")
    assert response.status_code == 404
    body = response.json()
    assert body["status"] == "error"
    assert "errno" not in body
