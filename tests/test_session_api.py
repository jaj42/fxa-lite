# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Session lifecycle: status, duplicate, reauth, destroy."""

from __future__ import annotations

import pytest

from conformance.client import AuthClient, ClientError
from conftest import EMAIL, PASSWORD


async def test_session_destroy_invalidates_the_token(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    assert await client.session_destroy(account["sessionToken"]) == {}
    with pytest.raises(ClientError) as caught:
        await client.session_status(account["sessionToken"])
    assert caught.value.errno == 110


async def test_session_destroy_accepts_an_empty_body(bearer_client: AuthClient) -> None:
    """Firefox sends `/session/destroy` with no payload at all."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    response = await bearer_client.http.post(
        "/v1/session/destroy",
        headers=bearer_client.authorization(account["sessionToken"], "sessionToken"),
    )
    assert response.status_code == 200


async def test_session_destroy_can_target_another_session(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    other = await bearer_client.sign_in(EMAIL, PASSWORD)

    await bearer_client.session_destroy(
        account["sessionToken"], {"customSessionToken": other["sessionToken"]}
    )
    # The named session is gone; the one that made the request survives.
    with pytest.raises(ClientError):
        await bearer_client.session_status(other["sessionToken"])
    assert (await bearer_client.session_status(account["sessionToken"]))["state"] == "verified"


async def test_session_destroy_refuses_another_accounts_session(
    bearer_client: AuthClient,
) -> None:
    mine = await bearer_client.sign_up(EMAIL, PASSWORD)
    theirs = await bearer_client.sign_up("someone-else@example.com", PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.session_destroy(
            mine["sessionToken"], {"customSessionToken": theirs["sessionToken"]}
        )
    assert caught.value.errno == 110
    assert (await bearer_client.session_status(theirs["sessionToken"]))["uid"] == theirs["uid"]


async def test_session_duplicate_keeps_the_original_auth_time(
    bearer_client: AuthClient,
) -> None:
    """A duplicate must not claim the password was just typed: `authAt` feeds the
    OAuth `auth_time` claim, and a fresh one would misreport the session's age."""
    account = await bearer_client.sign_in_or_up()
    original = await bearer_client.session_status(account["sessionToken"])

    duplicate = await bearer_client.session_duplicate(account["sessionToken"])
    assert duplicate["sessionToken"] != account["sessionToken"]
    assert duplicate["uid"] == account["uid"]
    assert duplicate["authAt"] == account["authAt"]
    assert duplicate["verified"] is True

    # Both tokens now work, independently.
    assert (await bearer_client.session_status(duplicate["sessionToken"]))["uid"] == original["uid"]
    assert (await bearer_client.session_status(account["sessionToken"]))["uid"] == original["uid"]


async def test_session_reauth_refreshes_auth_at_without_a_new_token(
    bearer_client: AuthClient,
) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    reauth = await bearer_client.session_reauth(account["sessionToken"], EMAIL, PASSWORD)
    assert "sessionToken" not in reauth
    assert reauth["uid"] == account["uid"]
    assert reauth["authAt"] >= account["authAt"]
    assert reauth["verified"] is True


async def test_session_reauth_can_mint_a_key_fetch_token(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD, keys=True)
    original = await bearer_client.account_keys(account["keyFetchToken"], account["unwrapBKey"])

    reauth = await bearer_client.session_reauth(
        account["sessionToken"], EMAIL, PASSWORD, keys=True
    )
    keys = await bearer_client.account_keys(reauth["keyFetchToken"], reauth["unwrapBKey"])
    assert keys == original


async def test_session_reauth_rejects_a_wrong_password(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.session_reauth(account["sessionToken"], EMAIL, "wrong password")
    assert caught.value.errno == 103


async def test_session_reauth_rejects_another_accounts_credentials(
    bearer_client: AuthClient,
) -> None:
    mine = await bearer_client.sign_up(EMAIL, PASSWORD)
    await bearer_client.sign_up("someone-else@example.com", PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.session_reauth(
            mine["sessionToken"], "someone-else@example.com", PASSWORD
        )
    assert caught.value.errno == 102
