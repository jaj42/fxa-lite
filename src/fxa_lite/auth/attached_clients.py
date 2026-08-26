# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`/v1/account/attached_clients` — devices, sessions and OAuth grants as one list.

Firefox polls this throughout a signed-in session, so a 404 here is not a
missing settings page: it is a request the browser keeps retrying forever.

The list is a *merge*, not a concatenation.  One browser shows up in as many as
three places — a device record, the session token that registered it, and the
refresh token its OAuth grant holds — and the point of the endpoint is that the
user sees one row for it.  `ConnectedServicesFactory` in
`fxa-shared/connected-services/factories.ts` does the merging upstream and
`merge` below is a transcription of it, keyed on the two pointers a device
record carries: its `sessionTokenId` and its `refreshTokenId`.

Two things fall out of fxa-lite's own design rather than from the reference:

- **Access tokens cannot appear.**  Upstream enumerates them from a table and
  folds each client that holds one but no refresh token into a row of its own.
  Here an access token is a JWT with no server-side row (phase 3), so there is
  nothing to enumerate — a client that holds only an access token is invisible
  until it takes a refresh token or registers a device.  In practice that is
  Firefox Desktop, which does hold both.
- **There is no localizer and no geo-IP.**  `createdTimeFormatted` and
  `lastAccessTimeFormatted` are the strings upstream's settings UI prints
  ("a month ago"); the keys are kept, empty, exactly as `attachedClientsDefaults`
  leaves them, because the only consumer is a settings page fxa-lite does not
  serve.  `location` is `{}` for the same reason `/account/devices` reports `{}`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Query, Request

from .. import accounts
from ..db import Database
from ..oauth.clients import Registry
from ..oauth.scopes import ScopeSet
from .credentials import Session, database
from .devices import last_access_time
from .user_agent import UserAgent, describe, parse, synthesize

router = APIRouter(tags=["devices"])


@dataclass(frozen=True, slots=True)
class AttachedDevice:
    """`AttachedDevice` — a device record, with the two pointers that merge it."""

    id: str
    session_token_id: str | None = None
    refresh_token_id: str | None = None
    name: str | None = None
    type: str | None = None
    created_at: int | None = None
    last_access_time: int | None = None


@dataclass(frozen=True, slots=True)
class AttachedOAuthClient:
    """`AttachedOAuthClient` — one authorized grant, as `authorized_clients.list` renders it."""

    client_id: str
    client_name: str
    refresh_token_id: str | None
    created_time: int
    last_access_time: int
    scope: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AttachedSession:
    """`AttachedSession` — a session token, plus what its User-Agent said."""

    id: str
    created_at: int
    last_access_time: int
    user_agent: UserAgent = field(default_factory=UserAgent)


@router.get("/account/attached_clients")
def attached_clients(
    request: Request,
    credentials: Session,
    filterIdleDevicesTimestamp: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    db: Database = database(request)
    db.touch_session_token(credentials.token.token_id, accounts.now_ms())
    uid = credentials.account.uid
    return merge(
        _devices(db, uid, filterIdleDevicesTimestamp),
        authorized_clients(db, request.app.state.clients, uid),
        _sessions(db, uid),
        credentials.token.token_id,
    )


@router.get("/account/attached_oauth_clients")
def attached_oauth_clients(request: Request, credentials: Session) -> list[dict[str, Any]]:
    """The same OAuth grants, one row per client, with only the two fields that matter.

    Upstream reaches this through the same factory with the device and session
    lists stubbed out, then throws away every field but these two. Skipping the
    factory here says what the endpoint is instead of what it was built from.
    """
    db: Database = database(request)
    db.touch_session_token(credentials.token.token_id, accounts.now_ms())
    clients = authorized_clients(
        db, request.app.state.clients, credentials.account.uid, unique=True
    )
    return [
        {"clientId": client.client_id, "lastAccessTime": client.last_access_time}
        for client in clients
    ]


def merge(
    devices: list[AttachedDevice],
    oauth_clients: list[AttachedOAuthClient],
    sessions: list[AttachedSession],
    current_session_token_id: str,
) -> list[dict[str, Any]]:
    """`ConnectedServicesFactory.build` — devices first, then grants, then sessions.

    The order is load-bearing twice over. A device record is the only thing
    that can *claim* a session token or a refresh token, so it has to be seen
    before either; and a session token can grant itself any scope, so the
    sessions pass runs last in order to overwrite `scope` with `null`.
    """
    clients: list[dict[str, Any]] = []
    by_session_token: dict[str, dict[str, Any]] = {}
    by_refresh_token: dict[str, dict[str, Any]] = {}

    for device in devices:
        client = _defaults()
        client.update(
            sessionTokenId=device.session_token_id,
            # The device's `refreshTokenId` may be a dangling pointer; it is
            # only reported once a matching grant turns up below.
            refreshTokenId=None,
            deviceId=device.id,
            deviceType=device.type,
            name=device.name,
            createdTime=device.created_at,
            lastAccessTime=device.last_access_time,
        )
        clients.append(client)
        if device.session_token_id:
            by_session_token[device.session_token_id] = client
        if device.refresh_token_id:
            by_refresh_token[device.refresh_token_id] = client

    for grant in oauth_clients:
        client = by_refresh_token.get(grant.refresh_token_id or "")
        if client is not None:
            client["refreshTokenId"] = grant.refresh_token_id
        else:
            client = _defaults()
            client.update(
                refreshTokenId=grant.refresh_token_id,
                createdTime=grant.created_time,
                lastAccessTime=grant.last_access_time,
            )
            clients.append(client)
        client["clientId"] = grant.client_id
        client["scope"] = grant.scope
        client["createdTime"] = _earliest(client["createdTime"], grant.created_time)
        client["lastAccessTime"] = _latest(client["lastAccessTime"], grant.last_access_time)
        if not client["name"]:
            client["name"] = grant.client_name
        # Upstream assumes any OAuth client that registers a device record is a
        # mobile app (mozilla/fxa#449); fxa-lite has no better signal either.
        if client["deviceId"] and not client["deviceType"]:
            client["deviceType"] = "mobile"

    for session in sessions:
        client = by_session_token.get(session.id)
        if client is None:
            client = _defaults()
            client.update(sessionTokenId=session.id, createdTime=session.created_at)
            clients.append(client)
        client["createdTime"] = _earliest(client["createdTime"], session.created_at)
        client["lastAccessTime"] = _latest(client["lastAccessTime"], session.last_access_time)
        client["isCurrentSession"] = client["sessionTokenId"] == current_session_token_id
        # Anything holding a session token can grant itself any scope, so
        # naming a subset of them would be misleading rather than incomplete.
        client["scope"] = None
        client["userAgent"] = describe(session.user_agent)
        client["os"] = session.user_agent.os or None
        if not client["name"]:
            client["name"] = synthesize(session.user_agent)

    for client in clients:
        if client["deviceId"] and not client["deviceType"]:
            client["deviceType"] = "desktop"
        if client["name"]:
            client["name"] = client["name"].replace("Mac OS X", "macOS")
    return clients


def authorized_clients(
    db: Database, registry: Registry, uid: str, *, unique: bool = False
) -> list[AttachedOAuthClient]:
    """`authorized_clients.list` — every refresh token this account has issued.

    `unique` is `listUnique`: at most one row per client, the most recently
    used. Upstream needs a separate query for that because its rows come from
    MySQL; here the list is a handful of tokens and the fold is cheaper than a
    second statement.
    """
    grants = [
        AttachedOAuthClient(
            client_id=token.client_id,
            client_name=_client_name(registry, token.client_id),
            refresh_token_id=token.token_id,
            created_time=token.created_at,
            last_access_time=token.last_used_at,
            # Sorted, as upstream sorts them, so the output does not depend on
            # the order the client happened to ask for its scopes in.
            scope=sorted(ScopeSet.from_string(token.scope).values()),
        )
        for token in db.refresh_tokens(uid)
    ]
    if unique:
        newest: dict[str, AttachedOAuthClient] = {}
        for grant in grants:
            current = newest.get(grant.client_id)
            if current is None or grant.last_access_time > current.last_access_time:
                newest[grant.client_id] = grant
        grants = list(newest.values())
    return sorted(grants, key=_grant_order)


def _grant_order(grant: AttachedOAuthClient) -> tuple[int, str, int, str]:
    """`sortAuthorizedClients`: newest first, then name, creation, scope.

    The scope tiebreak compares the joined string because JavaScript's `>` on
    two arrays coerces both with `toString()`, which is `join(',')`.
    """
    return (
        -grant.last_access_time,
        grant.client_name,
        grant.created_time,
        ",".join(grant.scope),
    )


def _client_name(registry: Registry, client_id: str) -> str:
    """Upstream joins against the clients table; ours is the config's registry.

    A grant can outlive its client here — removing a `[[clients]]` entry does
    not delete the refresh tokens it was issued — so an unknown id falls back
    to itself rather than to a blank row nobody can identify.
    """
    client = registry.get(client_id)
    return client.name if client else client_id


def _devices(db: Database, uid: str, filter_idle_before: int | None) -> list[AttachedDevice]:
    devices = []
    for device in db.devices(uid):
        # "Sync currently considers devices that have been accessed in the last
        # 21 days to be active"; the client picks the cutoff, we just apply it.
        last_access = last_access_time(db, device)
        if filter_idle_before and last_access <= filter_idle_before:
            continue
        devices.append(
            AttachedDevice(
                id=device.id,
                session_token_id=device.session_token_id,
                refresh_token_id=device.refresh_token_id,
                name=device.name or None,
                type=device.type or None,
                created_at=device.created_at,
                last_access_time=last_access,
            )
        )
    return devices


def _sessions(db: Database, uid: str) -> list[AttachedSession]:
    return [
        AttachedSession(
            id=token.token_id,
            created_at=token.created_at,
            last_access_time=token.last_access_time,
            user_agent=parse(token.user_agent),
        )
        for token in db.session_tokens(uid)
    ]


def _defaults() -> dict[str, Any]:
    """`attachedClientsDefaults`, in the reference's own key order."""
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
        # `formatLocation` with nothing to format, and `formatTimestamps`
        # without a localizer — see the module docstring.
        "location": {},
        "userAgent": "",
        "os": None,
        "createdTimeFormatted": "",
        "lastAccessTimeFormatted": "",
    }


def _earliest(current: int | None, candidate: int) -> int:
    """`Math.min(current || Infinity, candidate)` — falsy means "not yet known"."""
    return candidate if not current else min(current, candidate)


def _latest(current: int | None, candidate: int) -> int:
    """`Math.max(current || 0, candidate)`."""
    return candidate if not current else max(current, candidate)
