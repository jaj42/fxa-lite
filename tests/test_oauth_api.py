# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The OAuth tier, driven end to end through the conformance client.

The test that matters most is `test_sync_flow_recovers_the_oldsync_key`: it walks
the whole browser sign-in — password, `kB`, scoped-key metadata, `keys_jwe`,
code, token — and then checks the key that comes out the far end against a
derivation done straight from `kB`. If that passes, Firefox can decrypt its own
Sync records; if it fails, nothing else about phase 3 matters.
"""

import json

import pytest

from conformance.client import (
    FIREFOX_DESKTOP_CLIENT_ID,
    OLDSYNC_SCOPE,
    WEBCHANNEL_REDIRECT,
    AuthClient,
    ClientError,
    decode_jwt,
    derive_scoped_key,
    generate_relier_keypair,
    jwe_encrypt_ecdh_es,
    pkce_pair,
    public_jwk,
    verify_jwt,
)
from conftest import EMAIL, PASSWORD

FENIX_CLIENT_ID = "a2270f727f45f648"
SESSION_SCOPE = "https://identity.mozilla.com/tokens/session"


async def _account(client: AuthClient) -> dict:
    return await client.sign_up(EMAIL, PASSWORD)


@pytest.fixture
async def grant(bearer_client: AuthClient):
    """One full sign-in, shared by the tests that only inspect its results."""
    await _account(bearer_client)
    return await bearer_client.sync_sign_in(EMAIL, PASSWORD)


# -- the flow ----------------------------------------------------------------


async def test_sync_flow_recovers_the_oldsync_key(grant, db) -> None:
    """The key inside `keys_jwe` is the one `kB` implies, byte for byte.

    Derived here from `kB` and the account's own `keysChangedAt`, not from
    anything the flow returned, so the server has no way to make this agree
    except by being right.
    """
    account = db.account(grant.account["uid"])
    expected = derive_scoped_key(
        scope=OLDSYNC_SCOPE,
        kb=grant.keys["kB"],
        uid=account.uid,
        key_rotation_secret="00" * 32,
        key_rotation_timestamp=account.keys_changed_at,
    )
    assert grant.recovered_keys[OLDSYNC_SCOPE] == expected
    assert grant.recovered_keys == grant.scoped_keys
    assert len(expected["k"]) == 86, "oldsync keys are 64 bytes, base64url unpadded"


async def test_service_sync_resolves_to_scope(grant) -> None:
    """Firefox sends `service=sync` and no scope; the server fills it in."""
    assert grant.authorization["scope"] == f"{OLDSYNC_SCOPE} profile"
    assert grant.token["scope"] == f"{OLDSYNC_SCOPE} profile"


async def test_redirect_carries_code_and_state(grant) -> None:
    """Even for the WebChannel sentinel, which is a URN and not a location."""
    redirect = grant.authorization["redirect"]
    assert redirect.startswith(f"{WEBCHANNEL_REDIRECT}?")
    assert f"code={grant.authorization['code']}" in redirect
    assert f"state={grant.state}" in redirect


async def test_access_token_verifies_against_published_jwks(
    grant, bearer_client: AuthClient
) -> None:
    claims = verify_jwt(grant.access_token, await bearer_client.jwks())
    assert claims["sub"] == grant.account["uid"]
    assert claims["client_id"] == FIREFOX_DESKTOP_CLIENT_ID


async def test_oldsync_token_is_audienced_to_the_tokenserver(
    grant, bearer_client: AuthClient
) -> None:
    """The claim Sync hangs on — `aud` is the tokenserver, not the client id."""
    _, claims = decode_jwt(grant.access_token)
    assert claims["aud"] == "http://fxa.example.com/token"
    assert claims["iss"] == "http://fxa.example.com"
    assert claims["auth_time"] == grant.token["auth_at"]


async def test_non_sync_token_is_audienced_to_the_client(bearer_client: AuthClient) -> None:
    await _account(bearer_client)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, scope="profile")
    _, claims = decode_jwt(grant.access_token)
    assert claims["aud"] == FIREFOX_DESKTOP_CLIENT_ID


async def test_access_token_is_typed_as_an_access_token(grant) -> None:
    header, _ = decode_jwt(grant.access_token)
    assert header["typ"] == "at+JWT"
    assert header["alg"] == "RS256"


@pytest.mark.parametrize("scheme", ["bearer", "hawk"], indirect=False)
async def test_authorization_accepts_both_session_token_schemes(
    http, scheme: str, signing_keys
) -> None:
    client = AuthClient(http, scheme=scheme)
    account = await _account(client)
    _, challenge = pkce_pair()
    result = await client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="state",
        scope="profile",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert len(result["code"]) == 64


# -- authorization errors ----------------------------------------------------


async def test_authorization_requires_a_session_token(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.request(
            "POST", "/oauth/authorization", {"client_id": FIREFOX_DESKTOP_CLIENT_ID, "state": "s"}
        )
    assert caught.value.status == 401
    assert caught.value.errno == 110


async def test_unknown_client_is_rejected(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"], client_id="0" * 16, state="s", scope="profile"
        )
    assert caught.value.errno == 101


async def test_unregistered_redirect_uri_is_rejected(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            scope="profile",
            redirect_uri="https://evil.example.com/callback",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 103


async def test_public_client_must_use_pkce(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            scope="profile",
        )
    assert caught.value.errno == 118


async def test_scope_or_service_is_required(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 109


async def test_unknown_service_is_rejected(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            service="not-a-service",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 109


async def test_key_bearing_scope_outside_the_client_allowlist_is_refused(
    bearer_client: AuthClient,
) -> None:
    """Thunderbird's Sync scope is key-bearing, and no seeded client may have it."""
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            scope="https://identity.thunderbird.net/apps/sync",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 114


async def test_aal2_cannot_be_satisfied(bearer_client: AuthClient) -> None:
    """There is no second factor here, so `acr_values=AAL2` is refused outright."""
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            scope="profile",
            acr_values="AAL2",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 120


async def test_malformed_scope_is_a_parameter_error(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"],
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            state="s",
            scope="profile::email",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    assert caught.value.errno == 109


async def test_oauth_validation_errors_use_the_oauth_errno_table(
    bearer_client: AuthClient,
) -> None:
    """`109`, not the accounts API's `108` — a different route, a different table."""
    account = await _account(bearer_client)
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_authorization(
            account["sessionToken"], client_id=FIREFOX_DESKTOP_CLIENT_ID
        )
    assert caught.value.errno == 109


# -- token exchange ----------------------------------------------------------


async def test_codes_are_single_use(grant, bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            code=grant.authorization["code"],
            code_verifier="x" * 43,
        )
    assert caught.value.errno == 105


async def test_wrong_code_verifier_is_refused(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope="profile",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    other_verifier, _ = pkce_pair()
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            code=authorization["code"],
            code_verifier=other_verifier,
        )
    assert caught.value.errno == 117


async def test_missing_code_verifier_is_refused(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    _, challenge = pkce_pair()
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope="profile",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID, code=authorization["code"]
        )
    assert caught.value.errno == 118


async def test_a_code_belongs_to_the_client_that_asked_for_it(
    bearer_client: AuthClient,
) -> None:
    account = await _account(bearer_client)
    verifier, challenge = pkce_pair()
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope="profile",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FENIX_CLIENT_ID, code=authorization["code"], code_verifier=verifier
        )
    assert caught.value.errno == 106


async def test_expired_codes_are_refused(bearer_client: AuthClient, db, config) -> None:
    account = await _account(bearer_client)
    verifier, challenge = pkce_pair()
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope="profile",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    # Age the row rather than the clock: the TTL is minutes, and the test is
    # about the comparison, not about waiting for it.
    db.connection.execute(
        "UPDATE oauth_codes SET created_at = created_at - ?",
        ((config.ttl.authorization_code + 60) * 1000,),
    )
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            code=authorization["code"],
            code_verifier=verifier,
        )
    assert caught.value.errno == 107


async def test_unknown_grant_type_is_refused(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
        )
    assert caught.value.errno == 121


# -- the direct grant --------------------------------------------------------
#
# Firefox Desktop destroys the refresh token it is issued by the code flow and
# mints every later access token straight from its session token, so this grant
# is the one Sync actually runs on. See phase 8 in plan.md.


async def test_direct_grant_mints_an_access_token_from_a_session(
    grant, bearer_client: AuthClient
) -> None:
    minted = await bearer_client.oauth_token_from_session(
        grant.session_token, client_id=FIREFOX_DESKTOP_CLIENT_ID, scope=OLDSYNC_SCOPE
    )
    assert minted["scope"] == OLDSYNC_SCOPE
    assert minted["token_type"] == "bearer"
    # `access_type` defaulted to online, so there is nothing long-lived here.
    assert "refresh_token" not in minted

    _, claims = decode_jwt(minted["access_token"])
    assert claims["sub"] == grant.account["uid"]
    assert claims["scope"] == OLDSYNC_SCOPE


async def test_direct_grant_for_sync_is_audienced_to_the_tokenserver(
    grant, bearer_client: AuthClient, config
) -> None:
    """The claim Sync's whole authorization chain hangs off.

    A token minted this way has to be interchangeable with one from the code
    flow, and `aud` is where that would silently break: a token audienced to
    the client id is refused by the tokenserver.
    """
    minted = await bearer_client.oauth_token_from_session(
        grant.session_token, client_id=FIREFOX_DESKTOP_CLIENT_ID, scope=OLDSYNC_SCOPE
    )
    _, claims = decode_jwt(minted["access_token"])
    assert claims["aud"] == f"{config.public_url}/token"


async def test_direct_grant_requires_a_session_token(bearer_client: AuthClient) -> None:
    await _account(bearer_client)
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="fxa-credentials",
            scope="profile",
        )
    assert caught.value.code == 401
    assert caught.value.errno == 110


async def test_direct_grant_requires_a_scope(grant, bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token_from_session(
            grant.session_token, client_id=FIREFOX_DESKTOP_CLIENT_ID
        )
    assert caught.value.errno == 109


async def test_direct_grant_offline_also_returns_a_refresh_token(
    grant, bearer_client: AuthClient
) -> None:
    minted = await bearer_client.oauth_token_from_session(
        grant.session_token,
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        scope=OLDSYNC_SCOPE,
        access_type="offline",
    )
    assert minted["refresh_token"]


async def test_access_type_is_rejected_on_other_grants(
    grant, bearer_client: AuthClient
) -> None:
    """`Joi.forbidden()` upstream on every grant but the direct one."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token=grant.token["refresh_token"],
            access_type="offline",
        )
    assert caught.value.errno == 109


async def test_direct_grant_cannot_reach_a_scope_the_client_lacks(
    grant, bearer_client: AuthClient
) -> None:
    """A key-bearing scope outside the client's allow-list is an error, not a trim."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token_from_session(
            grant.session_token,
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            scope="https://identity.thunderbird.net/apps/sync",
        )
    assert caught.value.errno == 114


# -- refresh tokens ----------------------------------------------------------


async def test_refresh_token_mints_a_fresh_access_token(
    grant, bearer_client: AuthClient
) -> None:
    refreshed = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        grant_type="refresh_token",
        refresh_token=grant.token["refresh_token"],
    )
    assert refreshed["scope"] == grant.token["scope"]
    assert refreshed["access_token"] != grant.access_token
    # No new refresh token, and no authentication event to report.
    assert "refresh_token" not in refreshed
    assert "auth_at" not in refreshed


async def test_refresh_can_narrow_but_not_widen_scope(
    grant, bearer_client: AuthClient
) -> None:
    narrowed = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        grant_type="refresh_token",
        refresh_token=grant.token["refresh_token"],
        scope="profile",
    )
    assert narrowed["scope"] == "profile"

    # A trusted client may reach beyond the stored grant, but only into its own
    # allow-list; Thunderbird's Sync scope is in neither.
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token=grant.token["refresh_token"],
            scope="https://identity.thunderbird.net/apps/sync",
        )
    assert caught.value.errno == 114


async def test_refresh_drops_one_shot_scopes(grant, bearer_client: AuthClient) -> None:
    """`tokens/session` buys a session token once; a refresh token must not re-buy it."""
    refreshed = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        grant_type="refresh_token",
        refresh_token=grant.token["refresh_token"],
        scope=SESSION_SCOPE,
    )
    assert refreshed["scope"] == ""


async def test_online_grants_get_no_refresh_token(bearer_client: AuthClient) -> None:
    await _account(bearer_client)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, access_type="online")
    assert "refresh_token" not in grant.token


async def test_unknown_refresh_token_is_refused(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token="ab" * 32,
        )
    assert caught.value.errno == 108


async def test_refresh_token_belongs_to_one_client(grant, bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FENIX_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token=grant.token["refresh_token"],
        )
    assert caught.value.errno == 108


# -- verify, introspect, revoke ----------------------------------------------


async def test_verify_reports_the_grant(grant, bearer_client: AuthClient) -> None:
    info = await bearer_client.verify_token(grant.access_token)
    assert info["user"] == grant.account["uid"]
    assert info["client_id"] == FIREFOX_DESKTOP_CLIENT_ID
    assert set(info["scope"]) == {OLDSYNC_SCOPE, "profile"}


async def test_verify_rejects_a_token_we_did_not_sign(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.verify_token("not.a.jwt")
    assert caught.value.errno == 108


async def test_introspect_describes_an_access_token(grant, bearer_client: AuthClient) -> None:
    described = await bearer_client.introspect(grant.access_token)
    assert described["active"] is True
    assert described["token_type"] == "access_token"
    assert described["sub"] == grant.account["uid"]
    # Milliseconds here, seconds in `auth_time` — the reference's own units.
    assert described["exp"] - described["iat"] == grant.token["expires_in"] * 1000
    assert described["auth_time"] == grant.token["auth_at"]


async def test_introspect_describes_a_refresh_token(grant, bearer_client: AuthClient) -> None:
    described = await bearer_client.introspect(grant.token["refresh_token"])
    assert described["active"] is True
    assert described["token_type"] == "refresh_token"
    assert described["scope"] == grant.token["scope"]


async def test_introspect_reports_an_unknown_token_as_inactive(
    bearer_client: AuthClient,
) -> None:
    assert await bearer_client.introspect("cd" * 32) == {"active": False}


async def test_destroy_revokes_a_refresh_token(grant, bearer_client: AuthClient) -> None:
    assert await bearer_client.destroy_token(grant.token["refresh_token"]) == {}
    assert await bearer_client.introspect(grant.token["refresh_token"]) == {"active": False}
    with pytest.raises(ClientError):
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token=grant.token["refresh_token"],
        )


async def test_destroy_is_idempotent(bearer_client: AuthClient) -> None:
    """RFC 7009 §2.2: an unknown token is a success, not a 404."""
    assert await bearer_client.destroy_token("ef" * 32) == {}


async def test_destroy_checks_the_client(grant, bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.destroy_token(
            grant.token["refresh_token"], client_id=FENIX_CLIENT_ID
        )
    assert caught.value.errno == 108


async def test_legacy_destroy_revokes_a_refresh_token(
    grant, bearer_client: AuthClient
) -> None:
    """`POST /v1/destroy` — what Firefox for Android calls, and a 404 until now.

    Upstream exports this and `/v1/oauth/destroy` from one handler; the only
    difference is that here the payload names the kind of token it carries.
    """
    assert await bearer_client.destroy_token_legacy(
        refresh_token=grant.token["refresh_token"]
    ) == {}
    assert await bearer_client.introspect(grant.token["refresh_token"]) == {"active": False}


async def test_legacy_destroy_by_refresh_token_id(grant, bearer_client: AuthClient, db) -> None:
    """A client that kept the id rather than the token can still revoke it."""
    described = await bearer_client.introspect(grant.token["refresh_token"])
    assert await bearer_client.destroy_token_legacy(refresh_token_id=described["jti"]) == {}
    assert db.refresh_token(described["jti"]) is None


async def test_legacy_destroy_of_an_access_token_is_a_no_op(
    grant, bearer_client: AuthClient
) -> None:
    """There is no access-token table to delete a row from — see the handler.

    The `token` spelling is the one mobile sends for this; upstream renames it
    to `access_token` before looking at it.
    """
    assert await bearer_client.destroy_token_legacy(token=grant.access_token) == {}
    assert await bearer_client.destroy_token_legacy(access_token=grant.access_token) == {}


async def test_legacy_destroy_checks_the_client(grant, bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.destroy_token_legacy(
            refresh_token=grant.token["refresh_token"], client_id=FENIX_CLIENT_ID
        )
    assert caught.value.errno == 108


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"token": "ab" * 32, "refresh_token": "cd" * 32},
        {"refresh_token": "cd" * 32, "refresh_token_id": "ef" * 32},
    ],
)
async def test_legacy_destroy_takes_exactly_one_token(
    bearer_client: AuthClient, payload: dict
) -> None:
    """`.xor('access_token', 'refresh_token', 'refresh_token_id')`."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.destroy_token_legacy(**payload)
    assert caught.value.status == 400


# -- scoped key data ---------------------------------------------------------


async def test_scoped_key_data_reports_the_rotation_metadata(
    bearer_client: AuthClient, db
) -> None:
    account = await _account(bearer_client)
    data = await bearer_client.scoped_key_data(
        account["sessionToken"], FIREFOX_DESKTOP_CLIENT_ID, OLDSYNC_SCOPE
    )
    stored = db.account(account["uid"])
    assert data == {
        OLDSYNC_SCOPE: {
            "identifier": OLDSYNC_SCOPE,
            "keyRotationSecret": "00" * 32,
            "keyRotationTimestamp": stored.keys_changed_at,
        }
    }


async def test_scoped_key_data_omits_scopes_without_keys(bearer_client: AuthClient) -> None:
    account = await _account(bearer_client)
    data = await bearer_client.scoped_key_data(
        account["sessionToken"], FIREFOX_DESKTOP_CLIENT_ID, f"profile {OLDSYNC_SCOPE}"
    )
    assert list(data) == [OLDSYNC_SCOPE]


async def test_scoped_key_data_refuses_a_scope_the_client_may_not_have(
    bearer_client: AuthClient,
) -> None:
    account = await _account(bearer_client)
    with pytest.raises(ClientError) as caught:
        await bearer_client.scoped_key_data(
            account["sessionToken"],
            FIREFOX_DESKTOP_CLIENT_ID,
            "https://identity.thunderbird.net/apps/sync",
        )
    assert caught.value.errno == 114


# -- keys_jwe passthrough ----------------------------------------------------


async def test_keys_jwe_is_stored_and_echoed_verbatim(bearer_client: AuthClient) -> None:
    """The server never opens it; it must come back byte-identical."""
    account = await _account(bearer_client)
    relier_key = generate_relier_keypair()
    payload = json.dumps({"marker": "opaque"}).encode()
    keys_jwe = jwe_encrypt_ecdh_es(public_jwk(relier_key), payload)
    verifier, challenge = pkce_pair()
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope=OLDSYNC_SCOPE,
        keys_jwe=keys_jwe,
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    token = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        code=authorization["code"],
        code_verifier=verifier,
    )
    assert token["keys_jwe"] == keys_jwe


# -- client metadata ---------------------------------------------------------


async def test_client_info(bearer_client: AuthClient) -> None:
    info = await bearer_client.client_info(FIREFOX_DESKTOP_CLIENT_ID)
    assert info == {
        "id": FIREFOX_DESKTOP_CLIENT_ID,
        "name": "Firefox",
        "trusted": True,
        "image_uri": "",
        "redirect_uri": WEBCHANNEL_REDIRECT,
    }


async def test_client_info_for_an_unknown_client(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.client_info("0" * 16)
    assert caught.value.errno == 101


async def test_jwks_publishes_only_public_material(bearer_client: AuthClient) -> None:
    document = await bearer_client.jwks()
    assert len(document["keys"]) == 1
    key = document["keys"][0]
    assert set(key) >= {"kty", "kid", "alg", "use", "n", "e"}
    assert not set(key) & {"d", "p", "q", "dp", "dq", "qi"}
