# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Sync 1.5 storage, in SQL.

`syncstorage-mysql/src/db/{db_impl,batch_impl}.rs`.  Everything the HTTP tier
does eventually lands in one of these methods, and the rules they enforce are
the protocol's, not SQLite's:

* **Every write shares one timestamp.**  A `SyncStore` is built per request
  with `now` already quantized, and every row it writes gets that value.  A
  POST of fifty records is one instant, which is what lets a client ask for
  everything `newer=` that instant and get a consistent set.
* **A write must move the collection's timestamp forward.**  If the collection
  is already stamped at `now` or later, the write is refused as a conflict
  rather than landing at a timestamp a client has already polled past.  That is
  upstream's `lock_for_write`, and the 503 it produces is a documented, retried
  condition rather than a failure.
* **Expiry is absolute.**  A BSO's `ttl` arrives as seconds but is stored as
  the instant it dies, and expired rows are filtered out of every read rather
  than swept: there is no scheduler here, and a row nobody reads costs nothing.

Two upstream behaviours are *not* reproduced, both noted at their methods:
`do_append`'s missing `id` filter, and batches surviving a storage wipe.

The account-side statements live in `db.py`; these live here because they carry
a per-request session (that shared `now`, and the transaction around it) that
nothing in `db.py` has, and because the tier they belong to is the one that
would have been a separate service.
"""

from __future__ import annotations

import base64
import binascii
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from ..db import Database

#: `syncstorage-db-common`'s `DEFAULT_BSO_TTL`, in seconds: a shade over 66
#: years, which is upstream's way of spelling "forever".
DEFAULT_BSO_TTL = 2_100_000_000

#: `batch_impl.rs`'s `MAX_TTL`. A batch item with no ttl of its own is committed
#: with this as an *absolute* expiry in milliseconds -- not `now` plus it, which
#: is what the un-batched path does. Faithfully odd; see `commit_batch`.
MAX_TTL = 2_100_000_000

#: How long a batch may stay open. `syncstorage-db-common`'s `BATCH_LIFETIME`.
BATCH_LIFETIME_MS = 2 * 60 * 60 * 1000

#: `db_impl.rs`'s `DEFAULT_LIMIT`, itself `DEFAULT_MAX_TOTAL_RECORDS`.
DEFAULT_LIMIT = 10_000

#: The reserved `sync_collections` row that carries a deleted collection's mark
#: on the storage timestamp. `TOMBSTONE` upstream.
TOMBSTONE = 0

#: Sorting, spelled as the query string spells it. `None` is the absence of a
#: `sort` parameter and behaves as `newest` everywhere but `get_bso_ids`.
SORTINGS = ("newest", "oldest", "index")

#: `Sorting::None`, which is upstream's *default* variant and is spelled
#: `sort=none` on the wire (`syncstorage-db-common`'s enum carries
#: `#[serde(rename_all = "lowercase")]`).  It is accepted and then discarded:
#: `db_impl.rs` matches `Sorting::Newest | Sorting::None` together in `get_bsos`
#: and lets `None` fall through the `_` arm in `get_bso_ids`, which is exactly
#: what an absent `sort` already does here.  Naming it separately keeps
#: `SORTINGS` meaning "orders we can produce" rather than "strings we accept".
SORT_NONE = "none"


class StoreError(Exception):
    """Base for the conditions the HTTP tier turns into status codes."""


class CollectionNotFound(StoreError):
    """No such collection for this user. Often not an error — see `get_collection`."""


class BsoNotFound(StoreError):
    pass


class BatchNotFound(StoreError):
    pass


class ConflictError(StoreError):
    """This write would not move the collection's timestamp forward."""


@dataclass(frozen=True, slots=True)
class Bso:
    """One Basic Storage Object, as it leaves the database."""

    id: str
    modified: int
    payload: str
    sortindex: int | None
    expiry: int

    def as_json(self) -> dict[str, Any]:
        """The wire form. `sortindex` is omitted when unset; `expiry` never leaves."""
        body: dict[str, Any] = {
            "id": self.id,
            "modified": timestamp_json(self.modified),
            "payload": self.payload,
        }
        if self.sortindex is not None:
            body["sortindex"] = self.sortindex
        return body


@dataclass(frozen=True, slots=True)
class Page:
    """A result set plus the offset token that continues it."""

    items: list[Any]
    offset: str | None


@dataclass(frozen=True, slots=True)
class Offset:
    """`<timestamp>:<rows to skip>`, or a bare row count.

    The timestamp half is what makes pagination stable while records are being
    written: the second page is bounded by the first page's last `modified`
    rather than by a row number that shifts under it.
    """

    timestamp: int | None
    offset: int

    def __str__(self) -> str:
        if self.timestamp is None:
            return str(self.offset)
        return f"{self.timestamp}:{self.offset}"

    @classmethod
    def parse(cls, value: str) -> Offset:
        """`params::Offset::from_str`. Raises `ValueError` on anything else."""
        head, colon, tail = value.partition(":")
        if not colon:
            return cls(timestamp=None, offset=_non_negative(value))
        return cls(timestamp=quantize(_non_negative(head)), offset=_non_negative(tail))


def _non_negative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"negative offset component: {value}")
    return parsed


def quantize(milliseconds: int) -> int:
    """`SyncTimestamp::from_milliseconds`: round down to a whole hundredth.

    Sync timestamps are seconds with two decimal places, so the millisecond
    value the database holds always ends in a zero. Truncating on the way in
    rather than on the way out is what keeps `X-Last-Modified` and a later
    `?newer=` comparison agreeing exactly.
    """
    return milliseconds - (milliseconds % 10)


def timestamp_header(milliseconds: int) -> str:
    """`SyncTimestamp::as_header` — seconds, two decimals, always both."""
    return f"{milliseconds / 1000:.2f}"


def timestamp_json(milliseconds: int) -> float:
    """The same value as a JSON number.

    Upstream serializes through an arbitrary-precision number so that `0` reads
    as `0.00`; here it is a float, so a trailing zero is dropped. The value is
    identical and every client parses it as a number — Sync compares
    timestamps, it does not compare their spelling.
    """
    return round(milliseconds / 1000, 2)


def encode_next_offset(
    sort: str | None, prev_offset: int, prev_timestamp: int | None, modified: Sequence[int]
) -> str:
    """`util::encode_next_offset`.

    The subtle half is `skip`: the next page has to resume *after* the rows
    already returned that share the last row's timestamp, and there may be more
    of them than this page held. Counting the identical tail and, when the whole
    page shares one timestamp that the previous page also ended on, adding the
    previous skip, is what stops a record being served twice or missed.
    """
    if sort == "index":
        return str(prev_offset + len(modified))
    if not modified:
        return str(prev_offset)

    bound = modified[-1]
    skip = 1
    for value in reversed(modified[:-1]):
        if value != bound:
            break
        skip += 1
    if skip == len(modified) and prev_timestamp == bound:
        skip += prev_offset
    return str(Offset(timestamp=quantize(bound), offset=skip))


class SyncStore:
    """One user's storage, for the duration of one request."""

    def __init__(self, db: Database, uid: int, now: int) -> None:
        self.db = db
        self.uid = uid
        #: The single instant every write in this request is stamped with.
        self.now = now

    @property
    def connection(self) -> sqlite3.Connection:
        return self.db.connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.db.transaction() as connection:
            yield connection

    # -- collections ----------------------------------------------------------

    def collection_id(self, name: str) -> int:
        """Raises `CollectionNotFound`, which several callers treat as "empty"."""
        row = self.connection.execute(
            "SELECT id FROM sync_collections WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise CollectionNotFound(name)
        return int(row["id"])

    def get_or_create_collection_id(self, name: str) -> int:
        """Collection names are global, not per user: they are only ever ids here."""
        try:
            return self.collection_id(name)
        except CollectionNotFound:
            self.connection.execute(
                "INSERT OR IGNORE INTO sync_collections (name) VALUES (?)", (name,)
            )
            return self.collection_id(name)

    def collection_names(self, ids: Sequence[int]) -> dict[int, str]:
        if not ids:
            return {}
        # Interpolated: a run of `?`, one per id. The ids themselves are bound.
        placeholders = ",".join("?" * len(ids))
        rows = self.connection.execute(
            f"SELECT id, name FROM sync_collections WHERE id IN ({placeholders})",  # noqa: S608
            tuple(ids),
        )
        return {int(row["id"]): str(row["name"]) for row in rows}

    # -- timestamps -----------------------------------------------------------

    def storage_timestamp(self) -> int:
        """The newest thing that has happened to this user, tombstone included."""
        row = self.connection.execute(
            "SELECT MAX(modified) AS modified FROM sync_user_collections WHERE uid = ?",
            (self.uid,),
        ).fetchone()
        return int(row["modified"] or 0)

    def collection_timestamp(self, name: str) -> int:
        """Raises `CollectionNotFound` if this user has never written to it."""
        collection_id = self.collection_id(name)
        row = self.connection.execute(
            "SELECT modified FROM sync_user_collections WHERE uid = ? AND collection_id = ?",
            (self.uid, collection_id),
        ).fetchone()
        if row is None:
            raise CollectionNotFound(name)
        return int(row["modified"])

    def bso_timestamp(self, collection: str, bso_id: str) -> int:
        """Zero for a BSO that is not there — this feeds a precondition, not a read."""
        collection_id = self.collection_id(collection)
        row = self.connection.execute(
            "SELECT modified FROM sync_bso WHERE uid = ? AND collection_id = ? AND id = ?",
            (self.uid, collection_id, bso_id),
        ).fetchone()
        return int(row["modified"]) if row else 0

    def collection_timestamps(self) -> dict[str, int]:
        rows = self.connection.execute(
            """
            SELECT collection_id, modified FROM sync_user_collections
            WHERE uid = ? AND collection_id != ?
            """,
            (self.uid, TOMBSTONE),
        ).fetchall()
        names = self.collection_names([int(row["collection_id"]) for row in rows])
        return {names[int(row["collection_id"])]: int(row["modified"]) for row in rows}

    def collection_counts(self) -> dict[str, int]:
        rows = self.connection.execute(
            """
            SELECT collection_id, COUNT(*) AS n FROM sync_bso
            WHERE uid = ? AND expiry > ? GROUP BY collection_id
            """,
            (self.uid, self.now),
        ).fetchall()
        names = self.collection_names([int(row["collection_id"]) for row in rows])
        return {names[int(row["collection_id"])]: int(row["n"]) for row in rows}

    def collection_usage(self) -> dict[str, int]:
        """Payload bytes per collection. `LENGTH` counts characters in SQLite,
        which for a Sync payload — base64 inside JSON — is the same number."""
        rows = self.connection.execute(
            """
            SELECT collection_id, SUM(LENGTH(payload)) AS bytes FROM sync_bso
            WHERE uid = ? AND expiry > ? GROUP BY collection_id
            """,
            (self.uid, self.now),
        ).fetchall()
        names = self.collection_names([int(row["collection_id"]) for row in rows])
        return {names[int(row["collection_id"])]: int(row["bytes"] or 0) for row in rows}

    def storage_usage(self) -> int:
        row = self.connection.execute(
            "SELECT SUM(LENGTH(payload)) AS bytes FROM sync_bso WHERE uid = ? AND expiry > ?",
            (self.uid, self.now),
        ).fetchone()
        return int(row["bytes"] or 0)

    # -- reads ----------------------------------------------------------------

    def get_bso(self, collection: str, bso_id: str) -> Bso | None:
        collection_id = self.collection_id(collection)
        row = self.connection.execute(
            """
            SELECT id, modified, payload, sortindex, expiry FROM sync_bso
            WHERE uid = ? AND collection_id = ? AND id = ? AND expiry > ?
            """,
            (self.uid, collection_id, bso_id, self.now),
        ).fetchone()
        return _bso(row) if row else None

    def get_bsos(self, collection: str, query: BsoQuery, *, full: bool = True) -> Page:
        """The paginated collection read behind `GET /storage/{collection}`.

        `full=False` is not just a projection: `get_bso_ids` upstream is a
        separate query with a *different* offset token — a plain row count
        rather than a timestamp bound. Both are reproduced, because a client
        that pages ids and a client that pages records are handed tokens they
        each know how to send back.
        """
        collection_id = self.collection_id(collection)
        where = ["uid = ?", "collection_id = ?", "expiry > ?"]
        params: list[Any] = [self.uid, collection_id, self.now]

        bound = query.offset.timestamp if query.offset else None
        if full and bound is not None:
            # Resume where the previous page stopped, in the direction the sort
            # runs. `index` has no timestamp ordering to bound.
            if query.sort == "oldest":
                where.append("modified >= ?")
                params.append(bound)
            elif query.sort in (None, "newest"):
                where.append("modified <= ?")
                params.append(bound)
        if query.older is not None:
            where.append("modified < ?")
            params.append(query.older)
        if query.newer is not None:
            where.append("modified > ?")
            params.append(query.newer)
        if query.ids:
            where.append(f"id IN ({','.join('?' * len(query.ids))})")
            params.extend(query.ids)

        # A secondary sort on id: two records written in the same hundredth of a
        # second have no inherent order, and paginating an unstable order drops
        # records. The id is unique within a collection, so it settles it.
        orders = {
            "index": "ORDER BY sortindex DESC",
            "newest": "ORDER BY modified DESC, id DESC",
            "oldest": "ORDER BY modified ASC, id ASC",
        }
        # No `sort` means newest for records but *no order at all* for ids —
        # upstream's two queries differ here and a client paging ids relies on
        # the token it gets back, not on the order it gets them in.
        order = orders.get(query.sort or ("newest" if full else ""), "")

        # A request with no `limit` still gets one, which is upstream's own
        # `unwrap_or(DEFAULT_LIMIT)` and therefore *not* a divergence — it is
        # deliberately not marked as one, because the DIVERGENCE list means
        # "fxa-lite decided differently" and this is parity. It is written down
        # anyway because the edge it creates is invisible and shared with the
        # whole ecosystem: the Rust client every mobile build embeds does not
        # page. It reads `X-Weave-Next-Offset` nowhere (`sync15` has the header
        # constant and no call site) and says so in a comment at
        # `client/sync.rs` — "we just read them all in one request". So a
        # collection past DEFAULT_LIMIT records is silently truncated for a
        # phone, with no error on either side, and for bookmarks a truncated
        # tree is unmergeable. Raising the cap here would only move the cliff
        # and would put this server outside what clients have been tested
        # against; the honest answer is that the limit is upstream's and the
        # gap is the client's.
        limit = max(query.limit if query.limit is not None else DEFAULT_LIMIT, 0)
        numeric_offset = query.offset.offset if query.offset else 0
        columns = "id, modified, payload, sortindex, expiry" if full else "id"
        # One row more than asked for: its presence is how we know there is a
        # next page without counting the whole collection.
        # Every interpolated fragment above is a literal from this function:
        # `columns` is one of two fixed strings, `where` is built from literals
        # with `?` for each value, and `order` comes out of `orders` by lookup
        # — `query.sort` reaches SQL only as a dict key, never as text. Nothing
        # a request supplies is formatted into this string; it is all bound.
        sql = (
            f"SELECT {columns} FROM sync_bso WHERE {' AND '.join(where)} {order} "  # noqa: S608
            f"LIMIT ? OFFSET ?"
        )
        rows = self.connection.execute(
            sql, (*params, limit + 1 if limit > 0 else limit, numeric_offset)
        ).fetchall()

        records = [_bso(row) for row in rows] if full else []
        items: list[Any] = list(records) if full else [str(row["id"]) for row in rows]

        if limit >= 0 and len(items) > limit:
            items.pop()
            if full:
                records.pop()
                offset = encode_next_offset(
                    query.sort, numeric_offset, bound, [record.modified for record in records]
                )
            else:
                offset = str(limit + numeric_offset)
            return Page(items=items, offset=offset)
        # `limit=0` is a question, not a request: "is there anything here?".
        # Upstream answers the full-record form with an offset of 0 so the
        # client can then ask for the first page.
        return Page(items=items, offset="0" if (limit == 0 and full) else None)

    # -- writes ---------------------------------------------------------------

    def put_bso(
        self,
        collection: str,
        bso_id: str,
        *,
        payload: str | None = None,
        sortindex: int | None = None,
        ttl: int | None = None,
        collection_id: int | None = None,
        touch_collection: bool = True,
    ) -> int:
        """Create or update one record, returning the collection's new timestamp.

        A field the client did not send is a field it did not mean to change:
        an update with only a `sortindex` leaves the payload alone, and — this
        is the part that surprises — an update with *neither* a payload nor a
        sortindex does not even move `modified`, because nothing about the
        record the client can see has changed. Straight from upstream's
        conditional `ON DUPLICATE KEY UPDATE`.
        """
        if collection_id is None:
            collection_id = self.get_or_create_collection_id(collection)
        expiry = self.now + (DEFAULT_BSO_TTL if ttl is None else ttl) * 1000

        updates = []
        if sortindex is not None:
            updates.append("sortindex = excluded.sortindex")
        if payload is not None:
            updates.append("payload = excluded.payload")
        if ttl is not None:
            updates.append("expiry = excluded.expiry")
        if payload is not None or sortindex is not None:
            updates.append("modified = excluded.modified")
        # `updates` holds literal assignments chosen by which fields the
        # request set, not their values.
        conflict = f"DO UPDATE SET {', '.join(updates)}" if updates else "DO NOTHING"

        upsert = f"""
            INSERT INTO sync_bso (uid, collection_id, id, sortindex, payload, modified, expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(uid, collection_id, id) {conflict}
            """  # noqa: S608
        self.connection.execute(
            upsert,
            (
                self.uid,
                collection_id,
                bso_id,
                sortindex,
                payload if payload is not None else "",
                self.now,
                expiry,
            ),
        )
        if not touch_collection:
            return self.now
        return self.update_collection(collection_id)

    def post_bsos(self, collection: str, bsos: Sequence[Any], *, stamped: bool = False) -> int:
        """Write a list of records at one instant and stamp the collection once.

        `stamped` says this transaction has already moved the collection to
        `now`, which is true on exactly one path: a batch commit that also
        carries records.  There the guard has been satisfied by the commit
        itself, and applying it again makes the request conflict with its own
        write — the records land at the same instant as the batch, which is
        what a caller sending them with the commit asked for.
        """
        collection_id = self.get_or_create_collection_id(collection)
        if not stamped:
            self.check_write(collection_id)
        for bso in bsos:
            self.put_bso(
                collection,
                bso.id,
                payload=bso.payload,
                sortindex=bso.sortindex,
                ttl=bso.ttl,
                collection_id=collection_id,
                touch_collection=False,
            )
        return self.update_collection(collection_id)

    def delete_bso(self, collection: str, bso_id: str) -> int:
        collection_id = self.collection_id(collection)
        cursor = self.connection.execute(
            "DELETE FROM sync_bso WHERE uid = ? AND collection_id = ? AND id = ? AND expiry > ?",
            (self.uid, collection_id, bso_id, self.now),
        )
        if cursor.rowcount == 0:
            raise BsoNotFound(bso_id)
        return self.update_collection(collection_id)

    def delete_bsos(self, collection: str, ids: Sequence[str]) -> int:
        collection_id = self.collection_id(collection)
        if ids:
            # Again a run of `?`; the ids are bound alongside.
            delete = f"""
                DELETE FROM sync_bso
                WHERE uid = ? AND collection_id = ? AND id IN ({','.join('?' * len(ids))})
                """  # noqa: S608
            self.connection.execute(delete, (self.uid, collection_id, *ids))
        return self.update_collection(collection_id)

    def delete_collection(self, collection: str) -> int:
        """Remove a collection entirely; returns the *storage* timestamp.

        A vanished collection has no timestamp of its own left to report, so the
        deletion is recorded against the tombstone and the storage timestamp is
        what moves. That is what tells a client polling `/info/collections` that
        something changed even though nothing it can see is newer.
        """
        collection_id = self.collection_id(collection)
        deleted = self.connection.execute(
            "DELETE FROM sync_bso WHERE uid = ? AND collection_id = ?",
            (self.uid, collection_id),
        ).rowcount
        deleted += self.connection.execute(
            "DELETE FROM sync_user_collections WHERE uid = ? AND collection_id = ?",
            (self.uid, collection_id),
        ).rowcount
        if deleted == 0:
            raise CollectionNotFound(collection)
        self._erect_tombstone()
        return self.storage_timestamp()

    # DIVERGENCE: wipe-clears-open-batches — a storage wipe takes staged uploads with it
    #   upstream: leaves `batches`/`batch_uploads` rows behind, so a client that
    #     wipes and then commits a batch id it opened beforehand resurrects the
    #     records the wipe was meant to remove.
    #   fxa-lite: the wipe deletes the account's open batches and their items.
    #   why: "delete everything" that leaves a resurrection path behind is not
    #     the answer the route's name promises, and Firefox wipes storage exactly
    #     when it has decided the old records must not come back.
    #   cost: a commit of a batch opened before a wipe answers "batch not found"
    #     rather than landing. That is the intended answer.
    def delete_storage(self) -> None:
        """Everything, including the tombstone: the account starts over at zero."""
        self.connection.execute("DELETE FROM sync_bso WHERE uid = ?", (self.uid,))
        self.connection.execute("DELETE FROM sync_user_collections WHERE uid = ?", (self.uid,))
        # Upstream leaves open batches behind here, which is how a client that
        # wipes and then commits an id it opened beforehand resurrects records
        # the wipe was meant to remove. They go too.
        self.connection.execute("DELETE FROM sync_batch_items WHERE uid = ?", (self.uid,))
        self.connection.execute("DELETE FROM sync_batches WHERE uid = ?", (self.uid,))

    def check_write(self, collection_id: int) -> None:
        """`lock_for_write`: refuse a write that cannot advance the timestamp.

        Timestamps have hundredth-of-a-second resolution, so two writes to one
        collection inside the same hundredth would otherwise share an instant —
        and a client that has already polled `newer=` that instant would never
        see the second one. Upstream answers that with a conflict and so does
        this; `Retry-After` makes it a pause rather than a lost record.
        """
        row = self.connection.execute(
            "SELECT modified FROM sync_user_collections WHERE uid = ? AND collection_id = ?",
            (self.uid, collection_id),
        ).fetchone()
        if row is not None and int(row["modified"]) >= self.now:
            raise ConflictError(f"collection {collection_id} already stamped at {self.now}")

    def update_collection(self, collection_id: int) -> int:
        self.connection.execute(
            """
            INSERT INTO sync_user_collections (uid, collection_id, modified) VALUES (?, ?, ?)
            ON CONFLICT(uid, collection_id) DO UPDATE SET modified = excluded.modified
            """,
            (self.uid, collection_id, self.now),
        )
        return self.now

    def _erect_tombstone(self) -> None:
        self.update_collection(TOMBSTONE)

    # -- batches --------------------------------------------------------------

    def create_batch(self, collection: str) -> str:
        """Open a batch and return its id.

        The id is a millisecond timestamp — that is what makes `validate_batch`
        able to reject an expired one without touching the database. Upstream
        mixes in the low digit of the uid to spread its sharded writes; there is
        one table here, so the id is the timestamp and collisions are resolved
        by walking forward, as upstream does when its own mixing collides.
        """
        collection_id = self.get_or_create_collection_id(collection)
        batch_id = self.now
        for _ in range(MAX_BATCH_CREATE_RETRY):
            try:
                self.connection.execute(
                    """
                    INSERT INTO sync_batches (uid, batch_id, collection_id) VALUES (?, ?, ?)
                    """,
                    (self.uid, batch_id, collection_id),
                )
            except sqlite3.IntegrityError:
                batch_id += 1
                continue
            return encode_batch_id(batch_id)
        raise ConflictError("could not allocate a batch id")

    def validate_batch(self, collection: str, batch: str) -> bool:
        batch_id = decode_batch_id(batch)
        # An id older than the lifetime is dead whether or not the row is still
        # there, and saying so without a query is why the id is a timestamp.
        if batch_id + BATCH_LIFETIME_MS < self.now:
            return False
        try:
            collection_id = self.collection_id(collection)
        except CollectionNotFound:
            return False
        row = self.connection.execute(
            """
            SELECT 1 FROM sync_batches
            WHERE uid = ? AND batch_id = ? AND collection_id = ?
            """,
            (self.uid, batch_id, collection_id),
        ).fetchone()
        return row is not None

    # DIVERGENCE: batch-append-filters-id — a restaged record replaces only itself
    #   upstream: `do_append` updates the staged row without filtering on its id,
    #     so re-sending one record in a batch rewrites every record already staged.
    #   fxa-lite: the upsert is keyed on `(uid, batch_id, id)`, so a repeat
    #     replaces itself and nothing else — and replaces its `sortindex` too.
    #   why: it is a bug, it silently corrupts exactly the large uploads batching
    #     exists for, and reproducing it would mean writing the corruption twice.
    #   cost: a client relying on the upstream behaviour would be relying on data
    #     loss. None does; Firefox stages disjoint records.
    def append_to_batch(self, collection: str, batch: str, bsos: Sequence[Any]) -> None:
        """Stage records against an open batch.

        Upstream's `do_append` updates an existing item without filtering on its
        id, so re-sending one record in a batch rewrites every record already
        staged in it. That is a bug (it would silently corrupt a large upload),
        and it is not reproduced: an id sent twice replaces itself and nothing
        else. Unlike upstream, a repeat also replaces `sortindex`, since a
        client resending a record means the second copy.
        """
        if not self.validate_batch(collection, batch):
            raise BatchNotFound(batch)
        batch_id = decode_batch_id(batch)
        for bso in bsos:
            self.connection.execute(
                """
                INSERT INTO sync_batch_items (uid, batch_id, id, sortindex, payload, ttl_offset)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(uid, batch_id, id) DO UPDATE SET
                    sortindex  = excluded.sortindex,
                    payload    = excluded.payload,
                    ttl_offset = excluded.ttl_offset
                """,
                (self.uid, batch_id, bso.id, bso.sortindex, bso.payload, bso.ttl),
            )

    def commit_batch(self, collection: str, batch: str) -> int:
        """Land a whole batch in `sync_bso` at one timestamp.

        A staged field that was never set stays unset: a record already in the
        collection keeps its payload, sortindex or expiry rather than being
        blanked by a batch that only meant to change one of them. A record that
        is *new* and carried no ttl gets `MAX_TTL` milliseconds as an absolute
        instant — upstream's own arithmetic in `batch_commit.sql`, and a
        different "forever" from the one `put_bso` computes, reproduced rather
        than tidied because a client can read the record back and tell.

        Done row by row rather than as one `INSERT ... SELECT`: the insert and
        the conflict branches want different expressions for the same staged
        NULL (a default on the way in, "leave it alone" on the way over), and
        an upsert has only one set of values to offer both.
        """
        batch_id = decode_batch_id(batch)
        collection_id = self.get_or_create_collection_id(collection)
        staged = self.connection.execute(
            """
            SELECT id, sortindex, payload, ttl_offset FROM sync_batch_items
            WHERE uid = ? AND batch_id = ? ORDER BY id
            """,
            (self.uid, batch_id),
        ).fetchall()
        for item in staged:
            ttl_offset = item["ttl_offset"]
            expiry = MAX_TTL * 1000 if ttl_offset is None else self.now + ttl_offset * 1000
            self.connection.execute(
                """
                INSERT INTO sync_bso
                    (uid, collection_id, id, sortindex, payload, modified, expiry)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(uid, collection_id, id) DO UPDATE SET
                    modified  = excluded.modified,
                    sortindex = COALESCE(?, sync_bso.sortindex),
                    payload   = COALESCE(?, sync_bso.payload),
                    expiry    = COALESCE(?, sync_bso.expiry)
                """,
                (
                    self.uid,
                    collection_id,
                    item["id"],
                    item["sortindex"],
                    item["payload"] if item["payload"] is not None else "",
                    self.now,
                    expiry,
                    item["sortindex"],
                    item["payload"],
                    None if ttl_offset is None else expiry,
                ),
            )
        self.update_collection(collection_id)
        self.delete_batch(batch)
        return self.now

    def delete_batch(self, batch: str) -> None:
        batch_id = decode_batch_id(batch)
        self.connection.execute(
            "DELETE FROM sync_batch_items WHERE uid = ? AND batch_id = ?", (self.uid, batch_id)
        )
        self.connection.execute(
            "DELETE FROM sync_batches WHERE uid = ? AND batch_id = ?", (self.uid, batch_id)
        )


#: `batch_impl.rs`'s `MAX_BATCH_CREATE_RETRY`.
MAX_BATCH_CREATE_RETRY = 5


@dataclass(frozen=True, slots=True)
class BsoQuery:
    """The `?newer=&older=&sort=&limit=&offset=&ids=` half of a collection read."""

    newer: int | None = None
    older: int | None = None
    sort: str | None = None
    limit: int | None = None
    offset: Offset | None = None
    ids: tuple[str, ...] = ()


def encode_batch_id(batch_id: int) -> str:
    """Base64 of the *decimal text*, standard alphabet — `encode_id` upstream."""
    return base64.b64encode(str(batch_id).encode("ascii")).decode("ascii")


def decode_batch_id(value: str) -> int:
    """`decode_id`: base64 if it decodes, the raw string otherwise.

    The fallback is upstream's and is not decoration — the old Python server
    handed out bare decimal ids, and a client that still holds one must be able
    to commit it.
    """
    try:
        decoded = base64.b64decode(value, validate=True).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        decoded = value
    try:
        return int(decoded)
    except ValueError as exc:
        raise BatchNotFound(value) from exc


def _bso(row: sqlite3.Row) -> Bso:
    return Bso(
        id=str(row["id"]),
        modified=int(row["modified"]),
        payload=str(row["payload"]),
        sortindex=None if row["sortindex"] is None else int(row["sortindex"]),
        expiry=int(row["expiry"]),
    )


__all__ = [
    "BATCH_LIFETIME_MS",
    "DEFAULT_BSO_TTL",
    "DEFAULT_LIMIT",
    "MAX_TTL",
    "SORTINGS",
    "SORT_NONE",
    "TOMBSTONE",
    "BatchNotFound",
    "Bso",
    "BsoNotFound",
    "BsoQuery",
    "CollectionNotFound",
    "ConflictError",
    "Offset",
    "Page",
    "StoreError",
    "SyncStore",
    "decode_batch_id",
    "encode_batch_id",
    "encode_next_offset",
    "quantize",
    "timestamp_header",
    "timestamp_json",
]
