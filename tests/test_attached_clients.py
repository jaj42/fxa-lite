# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`/v1/account/attached_clients` — the merged list Firefox polls all session long.

The merge itself is pinned against the reference's own fixture, transcribed
from `lib/routes/attached-clients.spec.ts`, because it is the part with rules
rather than plumbing: which of three sources wins each field, and in what
order the rows come out.  The HTTP tests then check that fxa-lite's own tables
feed that function the right three lists.
"""

from __future__ import annotations

import pytest

from conformance.client import AuthClient, ClientError, get_credentials
from conftest import EMAIL, PASSWORD
from fxa_lite.auth.attached_clients import (
    AttachedDevice,
    AttachedOAuthClient,
    AttachedSession,
    merge,
)
from fxa_lite.auth.user_agent import UserAgent

FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"

NOW = 1_700_000_000_000

#: The ids the reference fixture generates randomly. Fixed here so the
#: expectations can name them; nothing in the merge looks at their shape.
DEVICE_1, DEVICE_2, DEVICE_3 = ("d1" * 16, "d2" * 16, "d3" * 16)
SESSION_0, SESSION_A, SESSION_C = ("50" * 32, "5a" * 32, "5c" * 32)
REFRESH_B, REFRESH_D, REFRESH_1 = ("rb" * 32, "rd" * 32, "r1" * 32)
CLIENT_LEGACY, CLIENT_SERVICE = ("c0" * 8, "c1" * 8)
CLIENT_DEVICE, CLIENT_MEGA = ("c2" * 8, "c3" * 8)


@pytest.fixture
def reference_fixture() -> tuple[list, list, list]:
    """`creates a merged list of all the things attached to the account`.

    Three devices — one owning a session, one owning a refresh token, one
    owning both — four OAuth grants, two of which are those devices, and three
    sessions, two of which are those devices.  Six rows should come out.
    """
    devices = [
        AttachedDevice(
            id=DEVICE_1,
            session_token_id=SESSION_A,
            type="desktop",
            name="device 1",
            created_at=NOW - 5,
        ),
        AttachedDevice(
            id=DEVICE_2,
            refresh_token_id=REFRESH_B,
            type="desktop",
            name="oauthy device-o",
            created_at=NOW - 2000,
        ),
        AttachedDevice(
            id=DEVICE_3,
            session_token_id=SESSION_C,
            refresh_token_id=REFRESH_D,
            created_at=NOW - 4000,
        ),
    ]
    oauth_clients = [
        AttachedOAuthClient(
            client_id=CLIENT_LEGACY,
            client_name="Legacy OAuth Service",
            refresh_token_id=None,
            created_time=NOW - 1600,
            last_access_time=NOW - 200,
            scope=["a", "b"],
        ),
        AttachedOAuthClient(
            client_id=CLIENT_SERVICE,
            client_name="OAuth Service",
            refresh_token_id=REFRESH_1,
            created_time=NOW - 1600,
            last_access_time=NOW - 200,
            scope=["profile"],
        ),
        AttachedOAuthClient(
            client_id=CLIENT_DEVICE,
            client_name="OAuth Device",
            refresh_token_id=REFRESH_B,
            created_time=NOW - 2600,
            last_access_time=NOW - 200,
            scope=["foo"],
        ),
        AttachedOAuthClient(
            client_id=CLIENT_MEGA,
            client_name="OAuth Mega-Device",
            refresh_token_id=REFRESH_D,
            created_time=NOW - 1600,
            last_access_time=NOW - 200,
            scope=["bar"],
        ),
    ]
    sessions = [
        AttachedSession(
            id=SESSION_0,
            created_at=NOW - 1234,
            last_access_time=NOW,
            user_agent=UserAgent(browser="Firefox", browser_version="67", os="Windows"),
        ),
        AttachedSession(id=SESSION_A, created_at=NOW, last_access_time=NOW),
        AttachedSession(id=SESSION_C, created_at=NOW, last_access_time=NOW),
    ]
    return devices, oauth_clients, sessions


def test_the_reference_fixture_merges_into_six_rows(reference_fixture) -> None:
    devices, oauth_clients, sessions = reference_fixture
    result = merge(devices, oauth_clients, sessions, SESSION_0)
    assert len(result) == 6

    # A device that owns a session: the device names it, the session dates it.
    assert result[0] == _row(
        deviceId=DEVICE_1,
        sessionTokenId=SESSION_A,
        deviceType="desktop",
        name="device 1",
        createdTime=NOW - 5,
        lastAccessTime=NOW,
    )
    # A device that owns a refresh token: the grant supplies clientId and scope,
    # and its earlier created_time wins.
    assert result[1] == _row(
        clientId=CLIENT_DEVICE,
        deviceId=DEVICE_2,
        refreshTokenId=REFRESH_B,
        deviceType="desktop",
        name="oauthy device-o",
        createdTime=NOW - 2600,
        lastAccessTime=NOW - 200,
        scope=["foo"],
    )
    # A device that owns both, and names neither itself: the grant names it, the
    # session blanks its scope, and "OAuth client with a device" means mobile.
    assert result[2] == _row(
        clientId=CLIENT_MEGA,
        deviceId=DEVICE_3,
        sessionTokenId=SESSION_C,
        refreshTokenId=REFRESH_D,
        deviceType="mobile",
        name="OAuth Mega-Device",
        createdTime=NOW - 4000,
        lastAccessTime=NOW,
    )
    # A grant with no refresh token at all — upstream's "legacy OAuth service",
    # a client holding only access tokens. fxa-lite can never produce one, but
    # the merge is the reference's and answers the same way if handed one.
    assert result[3] == _row(
        clientId=CLIENT_LEGACY,
        name="Legacy OAuth Service",
        createdTime=NOW - 1600,
        lastAccessTime=NOW - 200,
        scope=["a", "b"],
    )
    assert result[4] == _row(
        clientId=CLIENT_SERVICE,
        refreshTokenId=REFRESH_1,
        name="OAuth Service",
        createdTime=NOW - 1600,
        lastAccessTime=NOW - 200,
        scope=["profile"],
    )
    # A bare session: named from its User-Agent, and the one making the request.
    assert result[5] == _row(
        sessionTokenId=SESSION_0,
        isCurrentSession=True,
        name="Firefox 67, Windows",
        createdTime=NOW - 1234,
        lastAccessTime=NOW,
        userAgent="Firefox 67",
        os="Windows",
    )


def test_a_dangling_refresh_token_is_not_reported(reference_fixture) -> None:
    """`correctly handles device records with a dangling refresh token`.

    The device points at a refresh token that no longer exists, so the pointer
    must not come back — a client that tried to disconnect it would be asking
    the server to delete a row that is not there.
    """
    device = AttachedDevice(
        id=DEVICE_3,
        session_token_id=SESSION_C,
        refresh_token_id=REFRESH_D,
        created_at=NOW - 4000,
    )
    session = AttachedSession(id=SESSION_C, created_at=NOW, last_access_time=NOW)
    (row,) = merge([device], [], [session], SESSION_0)
    assert row["refreshTokenId"] is None
    assert row["clientId"] is None
    # Nothing said what kind of device this is, and it holds a session token
    # rather than a grant, so it is a desktop rather than upstream's mobile.
    assert row["deviceType"] == "desktop"


def test_mac_os_x_is_renamed_in_the_final_pass() -> None:
    session = AttachedSession(
        id=SESSION_0,
        created_at=NOW,
        last_access_time=NOW,
        user_agent=UserAgent(browser="Firefox", browser_version="130", os="Mac OS X"),
    )
    (row,) = merge([], [], [session], SESSION_0)
    assert row["name"] == "Firefox 130, macOS"
    # Only the name is rewritten; `os` still says what the User-Agent said.
    assert row["os"] == "Mac OS X"


def _row(**overrides) -> dict:
    """The reference's `attachedClientsDefaults`, with this row's fields applied.

    `location` and the two `*Formatted` strings are not parameters: fxa-lite
    has neither geo-IP nor a localizer, so they are constant.
    """
    return {
        "clientId": None,
        "deviceId": None,
        "sessionTokenId": None,
        "refreshTokenId": None,
        "isCurrentSession": False,
        "deviceType": None,
        "name": None,
        "createdTime": None,
        "lastAccessTime": 0,
        "scope": None,
        "location": {},
        "userAgent": "",
        "os": None,
        "createdTimeFormatted": "",
        "lastAccessTimeFormatted": "",
        **overrides,
    }


# --------------------------------------------------------------------------
# Over HTTP, against fxa-lite's own tables.
# --------------------------------------------------------------------------


async def test_a_fresh_session_is_one_row(client: AuthClient) -> None:
    account = await client.sign_up(EMAIL, PASSWORD)
    (row,) = await client.attached_clients(account["sessionToken"])
    assert row["sessionTokenId"] is not None
    assert row["isCurrentSession"] is True
    assert row["deviceId"] is None
    # A session token can grant itself anything, so naming scopes would mislead.
    assert row["scope"] is None


async def test_a_device_and_its_session_are_one_row(bearer_client: AuthClient) -> None:
    """The whole point of the endpoint: one browser, one row."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    device = await bearer_client.device_register(
        account["sessionToken"], {"name": "Work laptop", "type": "desktop"}
    )
    (row,) = await bearer_client.attached_clients(account["sessionToken"])
    assert row["deviceId"] == device["id"]
    assert row["name"] == "Work laptop"
    assert row["deviceType"] == "desktop"
    assert row["isCurrentSession"] is True


async def test_another_signed_in_session_is_a_second_row(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    await bearer_client.sign_in(EMAIL, PASSWORD)
    rows = await bearer_client.attached_clients(account["sessionToken"])
    assert len(rows) == 2
    # Exactly one of them is the session asking, and the other must not claim to be.
    assert [row["isCurrentSession"] for row in rows].count(True) == 1
    assert len({row["sessionTokenId"] for row in rows}) == 2


async def test_a_session_is_named_from_its_user_agent(bearer_client: AuthClient) -> None:
    """`synthesizeClientName`, from the header the sign-in request carried."""
    created = await bearer_client.http.post(
        "/v1/account/create",
        json={"email": EMAIL, "authPW": get_credentials(EMAIL, PASSWORD).auth_pw_hex},
        headers={"user-agent": FIREFOX_UA},
    )
    session_token = created.json()["sessionToken"]
    (row,) = await bearer_client.attached_clients(session_token)
    assert row["name"] == "Firefox 130, Linux"
    assert row["userAgent"] == "Firefox 130"
    assert row["os"] == "Linux"


async def test_an_oauth_grant_is_its_own_row(bearer_client: AuthClient) -> None:
    """fxa-lite's devices are registered by a session token, never by a grant.

    So a Sync sign-in produces two rows rather than one: the browser's session
    and the refresh token it holds. Upstream merges them only when the device
    record itself names the refresh token, which our `/account/device` has no
    way to do.
    """
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    rows = await bearer_client.attached_clients(grant.session_token)

    oauth_rows = [row for row in rows if row["clientId"]]
    assert len(oauth_rows) == 1
    row = oauth_rows[0]
    assert row["name"] == "Firefox"
    assert row["refreshTokenId"] is not None
    assert "https://identity.mozilla.com/apps/oldsync" in row["scope"]
    # Sorted, so the output does not depend on the order the client asked in.
    assert row["scope"] == sorted(row["scope"])


async def test_an_access_token_alone_is_invisible(bearer_client: AuthClient) -> None:
    """An online grant takes no refresh token, and fxa-lite stores no access
    tokens — so it leaves nothing behind for the list to report.

    The two rows are the sign-up's session and the sign-in's; neither carries a
    client id, which is the whole assertion.
    """
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, access_type="online")
    rows = await bearer_client.attached_clients(grant.session_token)
    assert [row["clientId"] for row in rows] == [None, None]


async def test_idle_devices_can_be_filtered_out(bearer_client: AuthClient) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    await bearer_client.device_register(account["sessionToken"], {"name": "Laptop"})
    rows = await bearer_client.attached_clients(
        account["sessionToken"], filter_idle_devices_timestamp=2_000_000_000_000
    )
    # The device is gone, but the session that owns it is not: the filter drops
    # device records, not the account's sessions.
    assert [row["deviceId"] for row in rows] == [None]


async def test_the_list_needs_a_session_token(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.request("GET", "/account/attached_clients")
    assert caught.value.errno == 110


async def test_reading_the_list_marks_the_session_as_seen(bearer_client: AuthClient) -> None:
    """`db.touchSessionToken` — polling this is itself evidence of activity."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    (before,) = await bearer_client.attached_clients(account["sessionToken"])
    (after,) = await bearer_client.attached_clients(account["sessionToken"])
    assert after["lastAccessTime"] >= before["lastAccessTime"]


async def test_attached_oauth_clients_is_one_row_per_client(
    bearer_client: AuthClient,
) -> None:
    await bearer_client.sign_up(EMAIL, PASSWORD)
    first = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    await bearer_client.sync_sign_in(EMAIL, PASSWORD)

    rows = await bearer_client.attached_oauth_clients(first.session_token)
    assert len(rows) == 1
    assert set(rows[0]) == {"clientId", "lastAccessTime"}
    assert rows[0]["clientId"] == "5882386c6d801776"


async def test_attached_oauth_clients_is_empty_without_a_grant(
    bearer_client: AuthClient,
) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    assert await bearer_client.attached_oauth_clients(account["sessionToken"]) == []
