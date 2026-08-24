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
from .models import DeviceDestroy, DeviceRegistration
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
        session = (
            db.session_token(device.session_token_id) if device.session_token_id else None
        )
        last_access_time = session.last_access_time if session else device.created_at
        if filterIdleDevicesTimestamp and last_access_time <= filterIdleDevicesTimestamp:
            continue
        devices.append(
            {
                **_response(device),
                "isCurrentDevice": device.session_token_id == credentials.token.token_id,
                "lastAccessTime": last_access_time,
                "location": {},
            }
        )
    return devices


@router.post("/account/device/destroy")
def device_destroy(
    payload: DeviceDestroy, request: Request, credentials: Session
) -> dict[str, Any]:
    db: Database = database(request)
    if db.delete_device(credentials.account.uid, payload.id) is None:
        raise errors.unknown_device()
    return {}


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
