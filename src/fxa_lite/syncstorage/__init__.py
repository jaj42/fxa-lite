"""Sync 1.5 storage: the collections Firefox actually syncs into.

`syncserver/src/web/handlers.rs`, and the transaction wrapper around them in
`web/transaction.rs`.

Mounted at `/storage`, so the routes here are the `/1.5/{uid}/...` that the
tokenserver's `api_endpoint` points at.  Every one of them is authenticated by
a HAWK signature over the request itself (`hawk.py`), reads and writes through
a per-request `SyncStore` (`store.py`), and reports failure as a bare integer
(`errors.py`).

Four rules live in `_run` rather than in any one handler, because upstream
applies them in the layer *around* its handlers and a client relies on all four
being universal:

* **One transaction per request**, so a POST of several hundred records either
  lands or does not.
* **The resource timestamp** — of the storage, the collection, or the single
  record the URL names — is read inside that transaction, answers
  `X-If-Modified-Since` / `X-If-Unmodified-Since` before the handler runs, and
  becomes `X-Last-Modified` unless the handler set a better one.  Evaluating a
  precondition outside the transaction is the race the header exists to
  prevent.
* **A write must be able to move its collection's timestamp forward**, or it is
  refused as a conflict.  `store.check_write` explains why.
* **`X-Weave-Timestamp`** goes on every response, so a client can measure its
  clock skew from answers it is already receiving.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from ..db import Database
from . import credentials, errors, hawk, models
from . import store as store_module
from .store import (
    BatchNotFound,
    BsoNotFound,
    CollectionNotFound,
    ConflictError,
    Page,
    StoreError,
    SyncStore,
    quantize,
    timestamp_header,
    timestamp_json,
)

router = APIRouter(tags=["syncstorage"])

#: The one storage protocol version, and the segment `api_endpoint` names.
VERSION = "1.5"

#: `X-Last-Modified` for `/info/configuration`, which has no timestamp of its
#: own: the limits are constants, and were last modified at the epoch.
STATIC_LAST_MODIFIED = "0.00"

#: What resource a URL names, and therefore which timestamp answers a
#: precondition on it. `None` is the whole storage.
Resource = Callable[[SyncStore], int]


@dataclass(frozen=True, slots=True)
class SyncRequest:
    """A verified request and the store it will run against."""

    store: SyncStore
    credentials: credentials.SyncCredentials
    request: Request
    body: bytes


# --------------------------------------------------------------------------
# Authentication, the transaction, and the headers around every handler.
# --------------------------------------------------------------------------


async def _authenticate(request: Request, uid: int, *, read_body: bool) -> SyncRequest:
    """Verify the HAWK signature and open a store for the uid it names.

    The body is read before the signature is checked because the signature may
    cover it: a payload hash cannot be verified against a body nobody has read.
    """
    body = await request.body() if read_body else b""
    config = request.app.state.config
    secret: str = request.app.state.tokenserver_secret
    now_ms = int(time.time() * 1000)

    query = request.url.query
    verified = credentials.authenticate(
        header=request.headers.get("authorization"),
        secret=secret,
        method=request.method,
        resource=request.url.path + (f"?{query}" if query else ""),
        path=_mount_relative(request),
        origin=credentials.Origin.parse(config.public_url),
        now=now_ms // 1000,
        body=body if read_body else None,
        content_type=request.headers.get("content-type", ""),
    )
    if verified.uid != uid:
        # The path selects the data and the token authorizes it; a mismatch is
        # a token being spent against storage it was never issued for.
        raise errors.unauthorized()

    db: Database = request.app.state.db
    if db.sync_user(verified.uid) is None:
        # The account, or this generation of its keys, is gone. The token stays
        # cryptographically valid until it expires, so 401 is the only answer
        # that sends the client somewhere useful.
        raise errors.unauthorized()
    return SyncRequest(
        store=SyncStore(db, verified.uid, quantize(now_ms)),
        credentials=verified,
        request=request,
        body=body,
    )


def _mount_relative(request: Request) -> str:
    """The path below `/storage`, which is how the routes here are written."""
    root = request.scope.get("root_path") or ""
    path = request.url.path
    return path[len(root) :] if root and path.startswith(root) else path


def _run(
    sync: SyncRequest,
    handler: Callable[[SyncStore], Response],
    *,
    resource: Resource | None = None,
    collection: str | None = None,
) -> Response:
    """Open the transaction, check the precondition, run the handler, finish.

    `collection` marks this as a write against that collection — the caller
    passes it exactly when upstream would have taken a write lock.
    """
    resource = resource or SyncStore.storage_timestamp
    store = sync.store
    try:
        with store.transaction():
            timestamp = resource(store)
            response = _precondition(sync.request, timestamp)
            if response is None:
                if collection is not None:
                    store.check_write(store.get_or_create_collection_id(collection))
                response = handler(store)
                if "X-Last-Modified" not in response.headers:
                    response.headers["X-Last-Modified"] = timestamp_header(timestamp)
    except ConflictError as exc:
        raise errors.conflict() from exc
    except BatchNotFound as exc:
        # A well-formed id that no longer names anything: 400, matching the
        # Python server, because the client should open a new batch rather than
        # conclude the endpoint has moved.
        raise errors.bad_request() from exc
    except StoreError as exc:  # pragma: no cover - handlers catch their own
        raise errors.internal_error() from exc
    weave_timestamp(response, store.now)
    return response


def _precondition(request: Request, timestamp: int) -> Response | None:
    """`X-If-Modified-Since` / `X-If-Unmodified-Since`, checked against `timestamp`.

    Sending both is a 400: they contradict each other, and picking one would
    silently do the opposite of what the client asked half the time.
    """
    modified = request.headers.get("x-if-modified-since")
    unmodified = request.headers.get("x-if-unmodified-since")
    if modified is not None and unmodified is not None:
        raise errors.bad_request()
    status = None
    if modified is not None and timestamp <= models.parse_timestamp(modified):
        status = 304
    elif unmodified is not None and timestamp > models.parse_timestamp(unmodified):
        status = 412
    if status is None:
        return None
    return Response(
        status_code=status, headers={"X-Last-Modified": timestamp_header(timestamp)}
    )


def weave_timestamp(response: Response, now: int | None = None) -> None:
    """Stamp `X-Weave-Timestamp`: the server's clock, or the resource's own if later.

    Upstream's `set_weave_timestamp` middleware puts this on *every* response,
    errors included, and that is where it matters most: a client whose
    credential was just refused for clock skew learns the server's time from
    the refusal.
    """
    now = quantize(int(time.time() * 1000)) if now is None else now
    seconds = now / 1000
    if (header := response.headers.get("X-Last-Modified")) is not None:
        with contextlib.suppress(ValueError):  # pragma: no cover - we wrote it
            seconds = max(seconds, float(header))
    response.headers["X-Weave-Timestamp"] = f"{seconds:.2f}"


def _json(
    body: Any, *, headers: dict[str, str] | None = None, status_code: int = 200
) -> Response:
    return JSONResponse(body, status_code=status_code, headers=headers)


def _collection_resource(collection: str) -> Resource:
    def resolve(store: SyncStore) -> int:
        try:
            return store.collection_timestamp(collection)
        except CollectionNotFound:
            return 0

    return resolve


def _bso_resource(collection: str, bso: str) -> Resource:
    def resolve(store: SyncStore) -> int:
        try:
            return store.bso_timestamp(collection, bso)
        except CollectionNotFound:
            return 0

    return resolve


# --------------------------------------------------------------------------
# /info
# --------------------------------------------------------------------------


@router.get(f"/{VERSION}/{{uid:int}}/info/collections")
async def info_collections(uid: int, request: Request) -> Response:
    """Collection name -> last-modified. The first call of every sync."""
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        result = {
            name: timestamp_json(value) for name, value in store.collection_timestamps().items()
        }
        return _json(result, headers={"X-Weave-Records": str(len(result))})

    return _run(sync, handler)


@router.get(f"/{VERSION}/{{uid:int}}/info/collection_counts")
async def info_collection_counts(uid: int, request: Request) -> Response:
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        result = store.collection_counts()
        return _json(result, headers={"X-Weave-Records": str(len(result))})

    return _run(sync, handler)


@router.get(f"/{VERSION}/{{uid:int}}/info/collection_usage")
async def info_collection_usage(uid: int, request: Request) -> Response:
    """Kilobytes — the one place this API reports a unit it does not name."""
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        result = {name: value / 1024.0 for name, value in store.collection_usage().items()}
        return _json(result, headers={"X-Weave-Records": str(len(result))})

    return _run(sync, handler)


@router.get(f"/{VERSION}/{{uid:int}}/info/quota")
async def info_quota(uid: int, request: Request) -> Response:
    """`[used_kb, limit_kb]`. The limit is null because fxa-lite enforces none.

    A household's disk is the quota, and a number here would be a promise this
    server cannot keep: a client told it has room would still fail on a full
    filesystem, and one told it is out would stop syncing while space remained.
    """
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        return _json([store.storage_usage() / 1024.0, None])

    return _run(sync, handler)


@router.get(f"/{VERSION}/{{uid:int}}/info/configuration")
async def info_configuration(uid: int) -> Response:
    """The server's limits — and the one storage route with no authentication.

    Upstream's handler takes neither a credential nor a database connection.
    These are constants, identical for every user, and a client needs them
    before it can decide how to split an upload; requiring a token to learn a
    published constant would only produce clients that cannot ask.
    """
    response = _json(
        models.LIMITS.as_json(), headers={"X-Last-Modified": STATIC_LAST_MODIFIED}
    )
    weave_timestamp(response)
    return response


# --------------------------------------------------------------------------
# Whole storage
# --------------------------------------------------------------------------


@router.delete(f"/{VERSION}/{{uid:int}}")
@router.delete(f"/{VERSION}/{{uid:int}}/storage")
async def delete_all(uid: int, request: Request) -> Response:
    """Wipe this account's Sync data. Two spellings; the bare one is current.

    Answers `null`: there is no timestamp left to report because there is
    nothing left to have one. Upstream's handler serializes its unit type the
    same way.
    """
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        store.delete_storage()
        return _json(None)

    return _run(sync, handler)


# --------------------------------------------------------------------------
# Collections
# --------------------------------------------------------------------------


@router.get(f"/{VERSION}/{{uid:int}}/storage/{{collection}}")
async def get_collection(uid: int, collection: str, request: Request) -> Response:
    """Read a collection: ids by default, whole records with `?full`.

    A collection that does not exist is an empty list, not a 404 — a client
    syncing a collection for the first time asks for it before it can possibly
    exist, and an error there is indistinguishable from a real failure.
    """
    models.validate_collection(collection)
    sync = await _authenticate(request, uid, read_body=False)
    query = models.parse_query(request.query_params)
    full = "full" in request.query_params
    newlines = models.wants_newlines(request.headers.get("accept"))

    def handler(store: SyncStore) -> Response:
        try:
            page = store.get_bsos(collection, query, full=full)
        except CollectionNotFound:
            page = Page(items=[], offset=None)
        items = [item.as_json() for item in page.items] if full else page.items
        headers = {"X-Weave-Records": str(len(items))}
        if page.offset is not None:
            headers["X-Weave-Next-Offset"] = page.offset
        if newlines:
            return _newlines(items, headers)
        return _json(items, headers=headers)

    return _run(sync, handler, resource=_collection_resource(collection))


def _newlines(items: list[Any], headers: dict[str, str]) -> Response:
    """`application/newlines`: one JSON object per line.

    An embedded newline is escaped rather than emitted — a payload containing
    one would otherwise split a record in two, which the format has no way to
    signal and the client no way to notice.
    """
    body = "".join(
        json.dumps(item, separators=(",", ":")).replace("\n", "\\u000a") + "\n"
        for item in items
    )
    return Response(content=body, media_type="application/newlines", headers=headers)


@router.post(f"/{VERSION}/{{uid:int}}/storage/{{collection}}")
async def post_collection(uid: int, collection: str, request: Request) -> Response:
    """Store many records at once, optionally accumulating them into a batch."""
    models.validate_collection(collection)
    models.check_content_length(request.headers)
    models.check_batch_headers(request.headers)
    sync = await _authenticate(request, uid, read_body=True)
    batch = models.parse_batch(request.query_params)
    bsos = models.parse_bso_bodies(sync.body, request.headers.get("content-type"))
    models.check_known_bad_payload(bsos.valid, collection)

    def handler(store: SyncStore) -> Response:
        # `?batch=true&commit=true` in a single request is a batch of one
        # message, which is a plain POST. Upstream short-circuits it and so
        # does this: there is nothing to accumulate.
        if batch is not None and not (batch.id is None and batch.commit):
            return _post_batch(store, collection, batch, bsos)
        modified = store.post_bsos(collection, bsos.valid)
        return _json(
            {
                "modified": timestamp_json(modified),
                "success": [bso.id for bso in bsos.valid],
                "failed": bsos.invalid,
            },
            headers={"X-Last-Modified": timestamp_header(modified)},
        )

    return _run(
        sync, handler, resource=_collection_resource(collection), collection=collection
    )


def _post_batch(
    store: SyncStore, collection: str, batch: models.BatchRequest, bsos: models.PostedBsos
) -> Response:
    """Append to a batch, and commit it if asked.

    The 202 is the point of the whole mechanism: the records are held, nothing
    is visible to another device yet, and the collection's timestamp has not
    moved. Only the commit makes the upload real, all of it at one instant.
    """
    if batch.id is None:
        identifier = store.create_batch(collection)
    elif store.validate_batch(collection, batch.id):
        identifier = batch.id
    else:
        raise errors.bad_request()

    success = [bso.id for bso in bsos.valid]
    failed = dict(bsos.invalid)
    if bsos.valid and not batch.commit:
        store.append_to_batch(collection, identifier, bsos.valid)

    if not batch.commit:
        return _json(
            {"batch": identifier, "success": success, "failed": failed}, status_code=202
        )

    modified = store.commit_batch(collection, identifier)
    if bsos.valid:
        # Records sent *with* the commit are newer than anything staged under
        # the same id, so they are written after the batch lands rather than
        # into it. A client should not send them; clients do.
        modified = store.post_bsos(collection, bsos.valid)
    return _json(
        {"success": success, "failed": failed, "modified": timestamp_json(modified)},
        headers={"X-Last-Modified": timestamp_header(modified)},
    )


@router.delete(f"/{VERSION}/{{uid:int}}/storage/{{collection}}")
async def delete_collection(uid: int, collection: str, request: Request) -> Response:
    """Delete a whole collection, or just the ids named in `?ids=`."""
    models.validate_collection(collection)
    sync = await _authenticate(request, uid, read_body=False)
    query = models.parse_query(request.query_params)

    def handler(store: SyncStore) -> Response:
        try:
            if query.ids:
                modified = store.delete_bsos(collection, query.ids)
            else:
                modified = store.delete_collection(collection)
        except (CollectionNotFound, BsoNotFound):
            # Deleting what is not there is not a failure: the client wanted it
            # gone and it is gone. It gets the storage timestamp back.
            modified = store.storage_timestamp()
        headers = {"X-Last-Modified": timestamp_header(modified)} if query.ids else {}
        return _json(timestamp_json(modified), headers=headers)

    return _run(
        sync, handler, resource=_collection_resource(collection), collection=collection
    )


# --------------------------------------------------------------------------
# Single records
# --------------------------------------------------------------------------


@router.get(f"/{VERSION}/{{uid:int}}/storage/{{collection}}/{{bso}}")
async def get_bso(uid: int, collection: str, bso: str, request: Request) -> Response:
    models.validate_collection(collection)
    models.validate_bso_id(bso)
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        try:
            record = store.get_bso(collection, bso)
        except CollectionNotFound:
            record = None
        if record is None:
            raise errors.not_found()
        return _json(record.as_json())

    return _run(sync, handler, resource=_bso_resource(collection, bso))


@router.put(f"/{VERSION}/{{uid:int}}/storage/{{collection}}/{{bso}}")
async def put_bso(uid: int, collection: str, bso: str, request: Request) -> Response:
    models.validate_collection(collection)
    models.validate_bso_id(bso)
    models.check_content_length(request.headers)
    sync = await _authenticate(request, uid, read_body=True)
    body = models.parse_bso_body(sync.body, request.headers.get("content-type"))
    models.check_known_bad_payload([body], collection)

    def handler(store: SyncStore) -> Response:
        modified = store.put_bso(
            collection,
            bso,
            payload=body.payload,
            sortindex=body.sortindex,
            ttl=body.ttl,
        )
        return _json(
            timestamp_json(modified), headers={"X-Last-Modified": timestamp_header(modified)}
        )

    return _run(
        sync, handler, resource=_bso_resource(collection, bso), collection=collection
    )


@router.delete(f"/{VERSION}/{{uid:int}}/storage/{{collection}}/{{bso}}")
async def delete_bso(uid: int, collection: str, bso: str, request: Request) -> Response:
    models.validate_collection(collection)
    models.validate_bso_id(bso)
    sync = await _authenticate(request, uid, read_body=False)

    def handler(store: SyncStore) -> Response:
        try:
            modified = store.delete_bso(collection, bso)
        except (CollectionNotFound, BsoNotFound) as exc:
            raise errors.not_found() from exc
        return _json(
            {"modified": timestamp_json(modified)},
            headers={"X-Last-Modified": timestamp_header(modified)},
        )

    return _run(
        sync, handler, resource=_bso_resource(collection, bso), collection=collection
    )


__all__ = [
    "VERSION",
    "weave_timestamp",
    "credentials",
    "errors",
    "hawk",
    "models",
    "router",
    "store_module",
]
