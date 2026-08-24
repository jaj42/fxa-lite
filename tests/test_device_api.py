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


#: What Firefox sends after uploading the `clients` collection:
#: `clients.sys.mjs:_notifyCollectionChanged` through
#: `FxAccountsClient.notifyDevices`, which always sets `TTL` and names the local
#: device in `excluded` when `to` is `all`. This is the request that answered
#: 404 in the phase 8 trace.
COLLECTION_CHANGED = {
    "to": "all",
    "excluded": ["c" * 32],
    "payload": {
        "version": 1,
        "command": "sync:collection_changed",
        "data": {"collections": ["clients"], "reason": "firstsync"},
    },
    "TTL": 0,
}


async def test_devices_notify_is_refused_as_a_feature_this_server_lacks(
    bearer_client: AuthClient,
) -> None:
    """403/errno 202, which is upstream's own answer for a server with
    `deviceNotificationsEnabled = false` — true here permanently."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.devices_notify(account["sessionToken"], COLLECTION_CHANGED)
    assert caught.value.status == 403
    assert caught.value.errno == 202


async def test_devices_notify_never_asks_the_client_to_back_off(
    bearer_client: AuthClient,
) -> None:
    """The assertion this route exists to keep.

    `hawkclient.request` throws the parsed body whenever it carries `error`, and
    `FxAccountsClient._request` caches any error with a `retryAfter` as
    `backoffError` — rejecting *every* FxA request until the timer expires.
    `HawkClient._constructError` does the same from a `Retry-After` header, on
    any status. Firefox notifies on every sync, so either one would stall the
    account client on a permanently repeating timer.
    """
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    response = await bearer_client.http.post(
        "/v1/account/devices/notify",
        json=COLLECTION_CHANGED,
        headers=bearer_client.authorization(account["sessionToken"], "sessionToken"),
    )
    assert response.status_code == 403
    assert "retryAfter" not in response.json()
    assert "retry-after" not in response.headers


async def test_devices_notify_needs_a_session(bearer_client: AuthClient) -> None:
    """The credential is checked before the feature is: a 403 is a statement
    about this server, and an anonymous caller is owed nothing but 110."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.devices_notify("a" * 64, COLLECTION_CHANGED)
    assert caught.value.errno == 110


async def test_devices_notify_to_a_list_of_devices(bearer_client: AuthClient) -> None:
    """The schema's other alternative — Send Tab's shape, on older clients."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.devices_notify(
            account["sessionToken"],
            {"to": ["d" * 32], "payload": {"version": 1, "command": "fxaccounts:logout"}},
        )
    assert caught.value.errno == 202


@pytest.mark.parametrize(
    "payload",
    [
        # `excluded` is not a key of the alternative that names devices.
        {"to": ["d" * 32], "excluded": ["c" * 32], "payload": {}},
        {"to": "everyone", "payload": {}},
        {"to": "all", "payload": {}, "TTL": -1},
        {"to": "all", "payload": {}, "_endpointAction": "somethingElse"},
        {"to": "all"},
        {"to": "all", "payload": {}, "typo": True},
    ],
)
async def test_devices_notify_rejects_a_malformed_payload(
    bearer_client: AuthClient, payload: dict
) -> None:
    """Validation happens before the feature check, as it does upstream: a
    client bug should read as one rather than as a disabled feature."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.devices_notify(account["sessionToken"], payload)
    assert caught.value.status == 400
    assert caught.value.errno in (107, 108)
