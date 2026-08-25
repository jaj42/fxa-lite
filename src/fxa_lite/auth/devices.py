"""`/v1/account/device*` — the device registry behind Send Tab and the device list.

fxa-lite implements neither push nor device commands, but Firefox registers a
device record as part of connecting to Sync and treats a failure there as a
failed connection.  So the records are stored faithfully, echoed back in the
shape the reference uses, and simply never delivered to.

A device is owned by the credential that registered it — a session token for
Firefox Desktop, an OAuth refresh token for the mobile browsers, which never
hold a session token at all — and deleting the device deletes that credential
with it, which is what makes "disconnect this device" actually disconnect it.
Which of the two authenticated the request is `credentials.session` versus
`credentials.refresh`; see `credentials.device_credentials`.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Query, Request

from .. import accounts, errors
from ..db import Database, Device
from .credentials import DeviceAuth, DeviceCredentials, database
from .models import DeviceDestroy, DeviceRegistration, DevicesNotify
from .user_agent import parse, synthesize_name

router = APIRouter(tags=["devices"])


@router.post("/account/device")
def device_register(
    payload: DeviceRegistration, request: Request, credentials: DeviceAuth
) -> dict[str, Any]:
    """Create or update the device record this credential owns."""
    db: Database = database(request)
    user_agent = request.headers.get("user-agent", _session_user_agent(credentials))
    existing = _current_device(db, credentials)

    if payload.id:
        current = db.device(credentials.account.uid, payload.id)
        if current is None:
            raise errors.unknown_device()
        if existing is not None and existing.id != payload.id:
            raise errors.device_session_conflict(existing.id)
    else:
        # No id: update the record this credential already owns, if any, rather
        # than accumulating a new device on every reconnect. Firefox for Android
        # sends no id at all, so this is the only thing keeping its device list
        # to one row.
        current = existing

    device = _merge(payload, current, credentials, user_agent)
    db.upsert_device(device)
    return _response(device, created=current is None)


@router.get("/account/devices")
def device_list(
    request: Request,
    credentials: DeviceAuth,
    filterIdleDevicesTimestamp: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    db: Database = database(request)
    if credentials.session is not None:
        # "If this request is using a session token we bump the last access
        # time." A refresh token's is bumped when it is *spent*, at
        # `/v1/oauth/token`, and not by reading a list.
        db.touch_session_token(credentials.session.token_id, accounts.now_ms())

    devices = []
    for device in db.devices(credentials.account.uid):
        last_access = last_access_time(db, device)
        if filterIdleDevicesTimestamp and last_access <= filterIdleDevicesTimestamp:
            continue
        devices.append(
            {
                **_response(device),
                "isCurrentDevice": _is_current(device, credentials),
                "lastAccessTime": last_access,
                "location": {},
            }
        )
    return devices


def _is_current(device: Device, credentials: DeviceCredentials) -> bool:
    """Whichever pointer the caller authenticated with, matched against this row."""
    if credentials.session is not None:
        return device.session_token_id == credentials.session.token_id
    return device.refresh_token_id == credentials.refresh_token_id


def last_access_time(db: Database, device: Device) -> int:
    """When this device was last seen — which is when its credential was used.

    Upstream keeps `lastAccessTime` on the device row and refreshes it from the
    session token cache (`mergeDeviceAndSessionToken`). There is no cache here,
    so the session token is simply read; a device whose session is gone falls
    back to its own creation time, which is the last moment it was certainly
    there.

    A mobile device has no session token and its row would then never move, so
    the same question is asked of its refresh token instead — upstream's
    `/account/devices` says exactly this: "the devices table `lastAccessTime`
    column is not updated for OAuth-based FxA devices, so we get this
    information in the OAuth db".
    """
    if device.session_token_id:
        session = db.session_token(device.session_token_id)
        if session is not None:
            return session.last_access_time
    if device.refresh_token_id:
        refresh = db.refresh_token(device.refresh_token_id)
        if refresh is not None:
            return max(device.created_at, refresh.last_used_at)
    return device.created_at


# DIVERGENCE: device-commands-not-enabled — the command queue answers 403/errno 202
#   upstream: reads the queue with `pushbox.retrieve` and returns the pending
#     messages; with `config.pushbox.enabled = false` every pushbox method
#     rejects with `featureNotEnabled`, which is 403 / errno 202.
#   fxa-lite: always the latter. There is no pushbox and no `invoke_command`.
#   why: the queue is not empty, it does not exist. An empty-queue 200 is the
#     answer that never changes: it spends the client's polls telling it to ask
#     again instead of telling it why. errno 202 is in the client's own error
#     table; errno 116 (unknown endpoint) is not an answer about this feature.
#   cost: Send Tab and the other device commands do not work, which is the
#     out-of-scope list stated in the protocol's own words. `retryAfter` is
#     deliberately absent — see `errors.feature_not_enabled`.
@router.get("/account/device/commands")
def device_commands(
    request: Request,
    credentials: DeviceAuth,
    index: int | None = Query(default=None),
    limit: int = Query(default=100, ge=0, le=100),
) -> dict[str, Any]:
    """The receiving half of Send Tab — answered 403/errno 202, like a server with no pushbox.

    Phase 8 predicted this route would never be asked for and was wrong: Firefox
    for Android polls it (`?index=1`) once it has a device record, and until this
    existed the answer was a 404 with errno 116, "unknown endpoint" — which is
    only true of a server that has never heard of device commands, and says
    nothing about why they are not coming.

    Commands do not travel by push. The sender enqueues with
    `POST /account/devices/invoke_command`, push is only the nudge, and the
    target picks the message up here; upstream's handler reads the queue with
    `pushbox.retrieve`. fxa-lite has no pushbox and no `invoke_command`, so the
    queue is not empty, it does not exist — and upstream has an answer for
    precisely that deployment: with `config.pushbox.enabled = false` every
    pushbox method rejects with `featureNotEnabled`, so this route 403s with
    errno 202 while the rest of the device API keeps working.

    That last clause is why the other switch is the wrong one to copy.
    `oauth.deviceCommandsEnabled = false` also 403s `GET /account/devices` for a
    refresh-token caller — "the only reason a device calls this endpoint is to
    get a list of other devices it can send commands to" — and Android's device
    list has to keep answering.

    The alternative was `200 {"index": 0, "last": true, "messages": []}`, which
    is what an empty queue looks like and is not false: nothing is pending, and
    nothing can be. It is rejected for the reason `devices_notify` rejects its
    own 200 — it is the answer that never changes, and it spends the client's
    polls telling it to ask again rather than telling it why. errno 202 is in
    the client's error table (`auth-errors.js: FEATURE_NOT_ENABLED`); errno 116
    is not an answer about this feature at all.

    `retryAfter` is absent, as it must be on any permanent 403 here — see
    `errors.feature_not_enabled`. `index` and `limit` are declared but unread,
    so that a malformed one is still the 400 upstream's query validation gives
    rather than something this route invented; the queue behind them is what is
    missing, not the vocabulary.

    The unknown-device check comes first, because upstream's handler makes it
    before it touches pushbox: a caller with no device record of its own has
    asked about a queue that could not exist even here.
    """
    db: Database = database(request)
    if _current_device(db, credentials) is None:
        raise errors.unknown_device()
    raise errors.feature_not_enabled()


@router.post("/account/device/destroy")
def device_destroy(
    payload: DeviceDestroy, request: Request, credentials: DeviceAuth
) -> dict[str, Any]:
    db: Database = database(request)
    if db.delete_device(credentials.account.uid, payload.id) is None:
        raise errors.unknown_device()
    return {}


# DIVERGENCE: devices-notify-not-enabled — the push fan-out answers 403/errno 202
#   upstream: pushes the notification to the named devices; the same 403 / errno
#     202 when `deviceNotificationsEnabled` is off, a switch documented there as
#     temporary, for when client logic overloads the server.
#   fxa-lite: permanently that answer. There is no push service.
#   why: a 200 would promise a delivery that cannot happen, and Firefox treats
#     the promise as kept.
#   cost: a Sync write does not nudge the other devices, so they pick it up on
#     their next poll instead of at once. Again with no `retryAfter`: a
#     permanent 403 that carries one stalls the whole account client on a timer.
@router.post("/account/devices/notify")
def devices_notify(payload: DevicesNotify, credentials: DeviceAuth) -> dict[str, Any]:
    """Firefox's "the clients collection changed" nudge — answered 403/202.

    Sync sends this after uploading the `clients` collection, asking the server
    to push every *other* device awake so it picks the change up sooner
    (`clients.sys.mjs:_notifyCollectionChanged`). There is no push service here,
    so nothing can be woken.

    Both plausible answers are upstream's own, and the choice between them is
    which sentence is true of fxa-lite. `deviceNotificationsEnabled = false`
    answers 403/errno 202, and upstream's handler returns `200 {}` — even when
    `push.sendPush` throws, which it catches and logs. So a 200 is not a lie the
    protocol can detect (the response schema is the empty object; it claims
    nothing about delivery), but it is still a lie, and fxa-lite is exactly the
    deployment the 403 describes: device-driven notifications are off, and here
    permanently rather than as a safety switch. errno 202 is in the client's own
    error table (`auth-errors.js: FEATURE_NOT_ENABLED`), where a 404's errno 116
    is only "unknown endpoint".

    Nothing breaks either way: the caller does not await the promise and logs
    the rejection. What would break is a `retryAfter` on the answer — see
    `errors.feature_not_enabled`.

    Send Tab does not come through here. Current Firefox delivers commands with
    `POST /account/devices/invoke_command` and the target *polls*
    `/account/device/commands`; push is only the nudge. That is the route to
    implement if Send Tab is ever in scope, and it can be honest about delivery
    because its response carries `enqueued` and `notified` separately.
    """
    raise errors.feature_not_enabled()


def _current_device(db: Database, credentials: DeviceCredentials) -> Device | None:
    """The record this credential owns, by whichever pointer it has."""
    if credentials.session is not None:
        return db.device_by_session_token(credentials.session.token_id)
    if credentials.refresh is not None:
        return db.device_by_refresh_token(credentials.refresh.token_id)
    return None


def _session_user_agent(credentials: DeviceCredentials) -> str:
    """The fallback when the request has no `User-Agent` of its own.

    A refresh token has nowhere to have remembered one, so a mobile client that
    sends no header gets its name from its OAuth client instead — see `_merge`.
    """
    return credentials.session.user_agent if credentials.session else ""


def _merge(
    payload: DeviceRegistration,
    current: Device | None,
    credentials: DeviceCredentials,
    user_agent: str,
) -> Device:
    """Apply a registration payload over the stored record, filling the gaps."""
    name = payload.name if payload.name is not None else (current.name if current else "")
    if not name:
        # `devices.upsert`: an OAuth client's device is named after the client
        # before anything is synthesized from a User-Agent, because the client
        # name is the better answer and the header may not even be there.
        name = (credentials.client.name if credentials.client else "") or synthesize_name(
            user_agent
        )
    device_type = payload.type or (current.type if current else "")
    if not device_type:
        # "For now we assume that all oauth clients that register a device
        # record are mobile apps" (mozilla/fxa#449).
        if credentials.refresh is not None:
            device_type = "mobile"
        else:
            device_type = "mobile" if parse(user_agent).is_mobile else "desktop"

    push_callback = _pick(payload.pushCallback, current, "push_callback")
    # A new push endpoint has not expired yet; only an unchanged one keeps its
    # expiry flag. Upstream resets the flag on registration for the same reason.
    expired = bool(current and current.push_endpoint_expired)
    if current is None or (payload.pushCallback and payload.pushCallback != current.push_callback):
        expired = False

    return Device(
        id=payload.id or (current.id if current else secrets.token_hex(16)),
        uid=credentials.account.uid,
        session_token_id=credentials.session_token_id,
        refresh_token_id=credentials.refresh_token_id,
        name=name,
        type=device_type,
        created_at=current.created_at if current else accounts.now_ms(),
        push_callback=push_callback,
        push_public_key=_pick(payload.pushPublicKey, current, "push_public_key"),
        push_auth_key=_pick(payload.pushAuthKey, current, "push_auth_key"),
        push_endpoint_expired=expired,
        available_commands=(
            payload.availableCommands
            if payload.availableCommands is not None
            else (current.available_commands if current else {})
        ),
    )


def _pick(value: str | None, current: Device | None, attribute: str) -> str:
    if value is not None:
        return value
    return getattr(current, attribute) if current else ""


def _response(device: Device, created: bool = False) -> dict[str, Any]:
    """`buildDeviceResponse`: always the full record, defaults included."""
    response: dict[str, Any] = {
        "id": device.id,
        "name": device.name,
        "type": device.type,
        "pushCallback": device.push_callback,
        "pushPublicKey": device.push_public_key,
        "pushAuthKey": device.push_auth_key,
        "pushEndpointExpired": device.push_endpoint_expired,
        "availableCommands": device.available_commands,
    }
    if created:
        response["createdAt"] = device.created_at
    return response
