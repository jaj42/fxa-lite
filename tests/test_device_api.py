"""Device registration — the step Firefox takes on its way into Sync."""

from __future__ import annotations

import httpx
import pytest

from conformance.client import AuthClient, ClientError
from conftest import EMAIL, PASSWORD, PUBLIC_URL
from fxa_lite.app import create_app
from fxa_lite.config import from_dict

FIREFOX_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
)
FENIX_CLIENT_ID = "a2270f727f45f648"


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


# -- the mobile half: a device owned by a refresh token ----------------------
#
# Firefox for Android never holds a session token. It completes the OAuth flow,
# keeps the refresh token, and sends *that* as its bearer credential for every
# device call — `Bearer <64 hex>`, no `fxs_` prefix, a different table entirely
# (`auth-schemes/refresh-token.js`). Everything below is the same registry seen
# through that credential.


@pytest.fixture
async def phone(bearer_client: AuthClient) -> str:
    """A Fenix sign-in, reduced to the one thing the device routes need."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, client_id=FENIX_CLIENT_ID)
    return grant.token["refresh_token"]


async def test_a_refresh_token_can_register_a_device(
    bearer_client: AuthClient, phone: str
) -> None:
    device = await bearer_client.device_register(
        phone,
        {"name": "IronFox on Google Pixel 7", "type": "mobile"},
        kind="refreshToken",
    )
    assert len(device["id"]) == 32
    assert device["name"] == "IronFox on Google Pixel 7"
    assert device["type"] == "mobile"


async def test_a_refresh_token_device_is_named_after_its_client(
    bearer_client: AuthClient, phone: str
) -> None:
    """`devices.upsert`: no name, no User-Agent, so the OAuth client's name it is."""
    device = await bearer_client.device_register(phone, {}, kind="refreshToken")
    assert device["name"] == "Fenix"
    # "For now we assume that all oauth clients that register a device record
    # are mobile apps" — mozilla/fxa#449.
    assert device["type"] == "mobile"


async def test_a_refresh_token_re_registering_updates_one_row(
    bearer_client: AuthClient, phone: str
) -> None:
    """The reason `devices.refresh_token_id` is a unique index.

    Android sends no device id, so without a lookup on the refresh token every
    reconnect would leave another row behind — and the device list is what the
    other browsers send tabs to.
    """
    first = await bearer_client.device_register(phone, {"name": "Phone"}, kind="refreshToken")
    second = await bearer_client.device_register(phone, {"name": "Phone"}, kind="refreshToken")
    assert first["id"] == second["id"]
    assert len(await bearer_client.devices(phone, kind="refreshToken")) == 1


async def test_a_desktop_and_a_phone_are_two_devices(
    bearer_client: AuthClient, phone: str
) -> None:
    """Each credential owns its own row, and each one knows which is its own."""
    account = await bearer_client.sign_in(EMAIL, PASSWORD)
    await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    await bearer_client.device_register(phone, {"name": "Phone"}, kind="refreshToken")

    from_phone = await bearer_client.devices(phone, kind="refreshToken")
    assert {device["name"] for device in from_phone} == {"Laptop", "Phone"}
    assert [device["name"] for device in from_phone if device["isCurrentDevice"]] == ["Phone"]

    from_laptop = await bearer_client.devices(account["sessionToken"])
    assert [device["name"] for device in from_laptop if device["isCurrentDevice"]] == ["Laptop"]


async def test_a_phone_last_seen_when_its_refresh_token_was(
    bearer_client: AuthClient, phone: str, db
) -> None:
    """A mobile device has no session token to read a timestamp off.

    Upstream: "the devices table `lastAccessTime` column is not updated for
    OAuth-based FxA devices, so we get this information in the OAuth db".
    """
    device = await bearer_client.device_register(phone, {"name": "Phone"}, kind="refreshToken")
    record = db.device(db.account_by_email(EMAIL).uid, device["id"])
    db.touch_refresh_token(record.refresh_token_id, record.created_at + 60_000)

    listed = await bearer_client.devices(phone, kind="refreshToken")
    assert listed[0]["lastAccessTime"] == record.created_at + 60_000


async def test_destroying_a_phone_revokes_its_grant(
    bearer_client: AuthClient, phone: str
) -> None:
    """`devices.destroy` → `oauthDB.removeRefreshToken`.

    Disconnecting a device has to end its access, not just forget its name;
    for a mobile client the refresh token *is* the connection.
    """
    device = await bearer_client.device_register(phone, {"name": "Phone"}, kind="refreshToken")
    await bearer_client.device_destroy(phone, device["id"], kind="refreshToken")

    with pytest.raises(ClientError) as caught:
        await bearer_client.devices(phone, kind="refreshToken")
    assert caught.value.errno == 110
    with pytest.raises(ClientError):
        await bearer_client.oauth_token(
            client_id=FENIX_CLIENT_ID, grant_type="refresh_token", refresh_token=phone
        )


async def test_an_unknown_refresh_token_is_refused(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.device_register("f" * 64, {}, kind="refreshToken")
    assert caught.value.status == 401
    assert caught.value.errno == 110


async def test_devices_notify_from_a_phone_is_still_refused(
    bearer_client: AuthClient, phone: str
) -> None:
    """The credential is accepted; the feature is the thing that is not there."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.devices_notify(phone, COLLECTION_CHANGED, kind="refreshToken")
    assert caught.value.errno == 202


async def test_a_grant_that_may_not_manage_devices(db, signing_keys) -> None:
    """`config.oauth.deviceManagementClientIds` — the allowlist, and its point.

    A refresh token is not by itself permission to touch the device registry:
    upstream lets one through only if its client is on that list (which is the
    five browsers, `DEVICE_MANAGEMENT_CLIENT_IDS`) or its scopes include
    oldsync. A relier the household added to `[[clients]]` is neither, and the
    device list is where Send Tab delivers.
    """
    relier = "00112233445566aa"
    config = from_dict(
        {
            "public_url": PUBLIC_URL,
            "security": {"open_registration": True},
            "clients": [
                {
                    "id": relier,
                    "name": "Reader",
                    "redirect_uris": ["https://reader.example.com/oauth"],
                    "allowed_scopes": "profile",
                }
            ],
        }
    )
    app = create_app(config, db=db, signing_keys=signing_keys)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as http:
        client = AuthClient(http, scheme="bearer")
        account = await client.sign_up(EMAIL, PASSWORD)
        minted = await client.oauth_token_from_session(
            account["sessionToken"], client_id=relier, scope="profile", access_type="offline"
        )
        with pytest.raises(ClientError) as caught:
            await client.device_register(
                minted["refresh_token"], {"name": "Reader"}, kind="refreshToken"
            )
    assert caught.value.status == 401
    assert caught.value.errno == 110
