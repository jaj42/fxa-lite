"""Device registration — the step Firefox takes on its way into Sync."""

from __future__ import annotations

import pytest

from conformance.client import AuthClient, ClientError
from conftest import EMAIL, PASSWORD

FIREFOX_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
)


async def test_register_a_device(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    device = await client.device_register(
        account["sessionToken"], {"name": "Work laptop", "type": "desktop"}
    )
    assert len(device["id"]) == 32
    assert device["name"] == "Work laptop"
    assert device["type"] == "desktop"
    # `buildDeviceResponse` always answers with the full record, defaults included.
    assert device["pushCallback"] == ""
    assert device["pushEndpointExpired"] is False
    assert device["availableCommands"] == {}


async def test_registering_twice_updates_rather_than_duplicates(
    bearer_client: AuthClient,
) -> None:
    """Firefox re-registers on every reconnect; each one must land on the same row."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    first = await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    second = await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    assert first["id"] == second["id"]
    assert len(await bearer_client.devices(account["sessionToken"])) == 1


async def test_updating_a_device_by_id(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    device = await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    updated = await bearer_client.device_register(
        account["sessionToken"],
        {
            "id": device["id"],
            "name": "Renamed",
            "availableCommands": {"https://identity.mozilla.com/cmd/open-uri": "payload"},
        },
    )
    assert updated["id"] == device["id"]
    assert updated["name"] == "Renamed"
    assert updated["availableCommands"] == {
        "https://identity.mozilla.com/cmd/open-uri": "payload"
    }


async def test_updating_an_unknown_device(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.device_register(account["sessionToken"], {"id": "a" * 32})
    assert caught.value.errno == 123


async def test_a_session_cannot_claim_a_second_device(bearer_client: AuthClient) -> None:
    """One session, one device: the reference reports errno 124 rather than
    silently moving the session's ownership."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    other = await bearer_client.sign_in(EMAIL, PASSWORD)
    mine = await bearer_client.device_register(account["sessionToken"], {"name": "Mine"})
    theirs = await bearer_client.device_register(other["sessionToken"], {"name": "Theirs"})

    with pytest.raises(ClientError) as caught:
        await bearer_client.device_register(other["sessionToken"], {"id": mine["id"]})
    assert caught.value.errno == 124
    assert caught.value.body["deviceId"] == theirs["id"]


async def test_device_name_falls_back_to_the_user_agent(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    device = await bearer_client.authed(
        "POST", "/account/device", account["sessionToken"], "sessionToken", {}
    )
    # No name and no UA on this request, so nothing to synthesize from.
    assert device["name"] == ""

    response = await bearer_client.http.post(
        "/v1/account/device",
        json={"id": device["id"], "name": ""},
        headers={
            **bearer_client.authorization(account["sessionToken"], "sessionToken"),
            "user-agent": FIREFOX_UA,
        },
    )
    assert response.json()["name"] == "Firefox 130, Linux"


async def test_device_list_marks_the_current_device(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    other = await bearer_client.sign_in(EMAIL, PASSWORD)
    mine = await bearer_client.device_register(account["sessionToken"], {"name": "Mine"})
    theirs = await bearer_client.device_register(other["sessionToken"], {"name": "Theirs"})

    devices = {device["id"]: device for device in await bearer_client.devices(
        account["sessionToken"]
    )}
    assert devices[mine["id"]]["isCurrentDevice"] is True
    assert devices[theirs["id"]]["isCurrentDevice"] is False
    assert devices[theirs["id"]]["lastAccessTime"] > 0


async def test_device_destroy_also_ends_its_session(bearer_client: AuthClient) -> None:
    """Disconnecting a device is meant to sign it out, not merely forget its name."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    other = await bearer_client.sign_in(EMAIL, PASSWORD)
    theirs = await bearer_client.device_register(other["sessionToken"], {"name": "Theirs"})

    assert await bearer_client.device_destroy(account["sessionToken"], theirs["id"]) == {}
    assert await bearer_client.devices(account["sessionToken"]) == []
    with pytest.raises(ClientError) as caught:
        await bearer_client.session_status(other["sessionToken"])
    assert caught.value.errno == 110


async def test_device_destroy_of_an_unknown_device(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.device_destroy(account["sessionToken"], "b" * 32)
    assert caught.value.errno == 123


async def test_devices_disappear_with_the_account(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    await bearer_client.destroy_account(EMAIL, PASSWORD, account["sessionToken"])

    fresh = await bearer_client.sign_up(EMAIL, PASSWORD)
    assert await bearer_client.devices(fresh["sessionToken"]) == []


async def test_zero_length_capabilities_array_is_tolerated(bearer_client: AuthClient) -> None:
    """Some Firefox versions still send it; upstream accepts and drops it."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    device = await bearer_client.device_register(
        account["sessionToken"], {"name": "Laptop", "capabilities": []}
    )
    assert "capabilities" not in device
