"""`/v1/account/device*` — the device registry behind Send Tab and the device list.

fxa-lite implements neither push nor device commands, but Firefox registers a
device record as part of connecting to Sync and treats a failure there as a
failed connection.  So the records are stored faithfully, echoed back in the
shape the reference uses, and simply never delivered to.

A device is owned by the session token that registered it; deleting either one
deletes the other, which is what makes "disconnect this device" sign the
session out.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Query, Request

from .. import accounts, errors
from ..db import Database, Device
from .credentials import Session, SessionCredentials, database
from .models import DeviceDestroy, DeviceRegistration, DevicesNotify
from .user_agent import parse, synthesize_name

router = APIRouter(tags=["devices"])


@router.post("/account/device")
def device_register(
    payload: DeviceRegistration, request: Request, credentials: Session
) -> dict[str, Any]:
    """Create or update this session's device record."""
    db: Database = database(request)
    user_agent = request.headers.get("user-agent", credentials.token.user_agent)
    existing = db.device_by_session_token(credentials.token.token_id)

    if payload.id:
        current = db.device(credentials.account.uid, payload.id)
        if current is None:
            raise errors.unknown_device()
        if existing is not None and existing.id != payload.id:
            raise errors.device_session_conflict(existing.id)
    else:
        # No id: update the record this session already owns, if any, rather
        # than accumulating a new device on every reconnect.
        current = existing

    device = _merge(payload, current, credentials, user_agent)
    db.upsert_device(device)
    return _response(device, created=current is None)


@router.get("/account/devices")
def device_list(
    request: Request,
    credentials: Session,
    filterIdleDevicesTimestamp: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    db: Database = database(request)
    now = accounts.now_ms()
    db.touch_session_token(credentials.token.token_id, now)

    devices = []
    for device in db.devices(credentials.account.uid):
        last_access = last_access_time(db, device)
        if filterIdleDevicesTimestamp and last_access <= filterIdleDevicesTimestamp:
            continue
        devices.append(
            {
                **_response(device),
                "isCurrentDevice": device.session_token_id == credentials.token.token_id,
                "lastAccessTime": last_access,
                "location": {},
            }
        )
    return devices


def last_access_time(db: Database, device: Device) -> int:
    """When this device was last seen — which is when its session token was.

    Upstream keeps `lastAccessTime` on the device row and refreshes it from the
    session token cache (`mergeDeviceAndSessionToken`). There is no cache here,
    so the session token is simply read; a device whose session is gone falls
    back to its own creation time, which is the last moment it was certainly
    there.
    """
    session = db.session_token(device.session_token_id) if device.session_token_id else None
    return session.last_access_time if session else device.created_at


@router.post("/account/device/destroy")
def device_destroy(
    payload: DeviceDestroy, request: Request, credentials: Session
) -> dict[str, Any]:
    db: Database = database(request)
    if db.delete_device(credentials.account.uid, payload.id) is None:
        raise errors.unknown_device()
    return {}


@router.post("/account/devices/notify")
def devices_notify(payload: DevicesNotify, credentials: Session) -> dict[str, Any]:
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


def _merge(
    payload: DeviceRegistration,
    current: Device | None,
    credentials: SessionCredentials,
    user_agent: str,
) -> Device:
    """Apply a registration payload over the stored record, filling the gaps."""
    name = payload.name if payload.name is not None else (current.name if current else "")
    if not name:
        name = synthesize_name(user_agent)
    device_type = payload.type or (current.type if current else "")
    if not device_type:
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
        session_token_id=credentials.token.token_id,
        refresh_token_id=None,
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
