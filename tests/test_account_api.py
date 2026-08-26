# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The accounts API, driven through the same client a browser would use."""

from __future__ import annotations

import pytest

from conformance.client import AuthClient, ClientError, get_credentials
from conftest import EMAIL, PASSWORD
from fxa_lite.crypto import onepw, scoped_keys


async def test_create_returns_a_usable_session(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    assert len(account["uid"]) == 32
    assert len(account["sessionToken"]) == 64
    # No keys requested, so no key fetch token was minted.
    assert "keyFetchToken" not in account

    status = await bearer_client.session_status(account["sessionToken"])
    assert status == {
        "state": "verified",
        "uid": account["uid"],
        "details": {
            "accountEmailVerified": True,
            "sessionVerificationMethod": None,
            "sessionVerified": True,
            "sessionVerificationMeetsMinimumAAL": True,
            "verified": True,
        },
    }


async def test_create_rejects_a_duplicate_email(bearer_client: AuthClient) -> None:
    await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.sign_up(EMAIL.upper(), PASSWORD)
    assert caught.value.errno == 101


async def test_login_reports_verified_so_firefox_stops_polling(
    bearer_client: AuthClient,
) -> None:
    """Firefox polls `/recovery_email/status` until `verified`; nothing here can
    ever flip it later, so it has to be true from the start."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    account = await bearer_client.sign_in(EMAIL, PASSWORD)

    assert account["verified"] is True
    assert account["emailVerified"] is True
    assert account["sessionVerified"] is True

    status = await bearer_client.recovery_email_status(account["sessionToken"])
    assert status == {
        "email": EMAIL,
        "verified": True,
        "sessionVerified": True,
        "emailVerified": True,
    }


async def test_login_is_case_insensitive_on_the_domain(bearer_client: AuthClient) -> None:
    await bearer_client.sign_up(EMAIL, PASSWORD)
    # The stored spelling is what v1 stretching salts with, so a differently
    # cased login derives a different authPW and must be told which case to use.
    with pytest.raises(ClientError) as caught:
        await bearer_client.sign_in(EMAIL.upper(), PASSWORD)
    assert caught.value.errno == 120
    assert caught.value.body["email"] == EMAIL


async def test_login_with_the_wrong_password(bearer_client: AuthClient) -> None:
    await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.sign_in(EMAIL, PASSWORD + "!")
    assert caught.value.errno == 103
    assert caught.value.code == 400


async def test_login_to_an_unknown_account(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.sign_in("nobody@example.com", PASSWORD)
    assert caught.value.errno == 102


async def test_account_keys_round_trip(client: AuthClient) -> None:
    """The whole point of phase 2: a client that knows the password recovers kB.

    kA and kB are checked for shape and stability rather than against a fixed
    vector — they are freshly random per account — but the derivation path from
    `wrapWrapKb` through the bundle and back is exactly the protocol's.
    """
    account = await client.sign_up(EMAIL, PASSWORD, keys=True)
    keys = await client.account_keys(account["keyFetchToken"], account["unwrapBKey"])
    assert len(keys["kA"]) == 32
    assert len(keys["kB"]) == 32
    assert keys["kA"] != keys["kB"]

    # Signing in again produces a different keyFetchToken but the same keys.
    signed_in = await client.sign_in(EMAIL, PASSWORD, keys=True)
    assert signed_in["keyFetchToken"] != account["keyFetchToken"]
    again = await client.account_keys(signed_in["keyFetchToken"], signed_in["unwrapBKey"])
    assert again == keys


async def test_key_fetch_token_is_single_use(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD, keys=True)
    await bearer_client.account_keys(account["keyFetchToken"], account["unwrapBKey"])
    with pytest.raises(ClientError) as caught:
        await bearer_client.account_keys(account["keyFetchToken"], account["unwrapBKey"])
    assert caught.value.errno == 110
    assert caught.value.status == 401


async def test_kb_drives_the_sync_key(bearer_client: AuthClient) -> None:
    """kB is only useful if it is stable: it is the Sync encryption key, and a kB
    that changed between sign-ins would orphan every record already uploaded."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD, keys=True)
    first = await bearer_client.account_keys(account["keyFetchToken"], account["unwrapBKey"])

    signed_in = await bearer_client.sign_in(EMAIL, PASSWORD, keys=True)
    second = await bearer_client.account_keys(
        signed_in["keyFetchToken"], signed_in["unwrapBKey"]
    )
    assert first["kB"] == second["kB"]

    # And the client state the tokenserver will key on follows from it.
    assert scoped_keys.client_state(first["kB"]) == scoped_keys.client_state(second["kB"])


async def test_account_status(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    assert await bearer_client.account_status(account["uid"]) == {"exists": True}
    assert await bearer_client.account_status("0" * 32) == {"exists": False}

    by_email = await bearer_client.account_status_by_email(EMAIL)
    assert by_email["exists"] is True
    assert by_email["hasPassword"] is True
    assert (await bearer_client.account_status_by_email("nobody@example.com"))["exists"] is False


async def test_account_status_requires_a_uid_when_anonymous(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.request("GET", "/account/status")
    assert caught.value.errno == 108
    assert caught.value.body["param"] == "uid"


async def test_account_status_with_a_session(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    status = await client.authed(
        "GET", "/account/status", account["sessionToken"], "sessionToken"
    )
    assert status == {"exists": True, "locale": None, "hasPassword": True}


async def test_account_profile(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    profile = await client.account_profile(account["sessionToken"])
    assert profile["email"] == EMAIL
    assert profile["authenticatorAssuranceLevel"] == 1
    assert profile["keysChangedAt"] > 0


async def test_credentials_status_never_asks_for_a_v2_upgrade(
    bearer_client: AuthClient,
) -> None:
    """`upgradeNeeded: true` would send the client into a password change we
    cannot complete, since fxa-lite implements v1 stretching only."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    assert await bearer_client.credentials_status(EMAIL) == {
        "currentVersion": "v1",
        "upgradeNeeded": False,
    }


async def test_account_destroy(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    assert await client.destroy_account(EMAIL, PASSWORD, account["sessionToken"]) == {}
    assert await client.account_status(account["uid"]) == {"exists": False}

    # The session went with the account.
    with pytest.raises(ClientError) as caught:
        await client.session_status(account["sessionToken"])
    assert caught.value.errno == 110


async def test_account_destroy_needs_the_password(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.destroy_account(EMAIL, "not the password", account["sessionToken"])
    assert caught.value.errno == 103
    assert (await bearer_client.account_status(account["uid"]))["exists"] is True


async def test_get_random_bytes(bearer_client: AuthClient) -> None:
    first = await bearer_client.request("POST", "/get_random_bytes")
    second = await bearer_client.request("POST", "/get_random_bytes")
    assert len(first["data"]) == 64
    assert first != second


async def test_the_server_derives_the_same_auth_pw_as_the_test_client() -> None:
    """The conformance client duplicates the derivation on purpose; this asserts
    the duplicate agrees, so a divergence surfaces here and not as a mystery 103."""
    ours = get_credentials(EMAIL, PASSWORD)
    theirs = onepw.credentials_v1(EMAIL, PASSWORD)
    assert ours.auth_pw == theirs.auth_pw
    assert ours.unwrap_b_key == theirs.unwrap_b_key
