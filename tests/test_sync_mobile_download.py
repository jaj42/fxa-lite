"""The one request shape every mobile download uses, driven over HTTP.

Firefox for Android is not JavaScript: it embeds the Rust `sync15` crate, and
that crate's collection read is much narrower than Desktop's.  The bookmarks
engine issues exactly

    GET <api_endpoint>/storage/bookmarks?full=1&newer=<since>

and nothing else -- no `sort`, no `limit`, no `ids`, no `offset`, and it never
pages, because `X-Weave-Next-Offset` has no reader anywhere in the crate.  It
issues even that only when `info/collections` disagrees with the high-water
mark it stored last time, compared for *exact* equality; equal means the
request is never made and the sync reports success having downloaded nothing.

None of that had a test.  `?newer=` had never been driven through the HTTP tier
at all -- it was covered at the store level, where the value arrives as an
integer instead of as a float in a query string -- so the round trip from an
`X-Last-Modified` a client was handed back to the records that answer it was
unverified end to end.  A household reported desktop records not reaching a
phone, and closing that report meant arguing from a reading rather than from a
run.  This module is the run.

`MobileEngine` below is the client's rule, not ours: it mirrors
`places/src/bookmark_sync/engine.rs`'s `get_collection_request` and where that
file writes its high-water mark, so a test that fetches when the real client
would skip cannot pass by accident.
"""

from __future__ import annotations

from typing import Any

import pytest

from conformance.client import (
    OLDSYNC_SCOPE,
    AuthClient,
    SyncStorageClient,
    TokenserverClient,
    expect_ok,
    server_timestamp,
    sync_key_id,
)
from conftest import EMAIL, PASSWORD


@pytest.fixture
async def pair(
    bearer_client: AuthClient, tokenserver: TokenserverClient, http, tokenserver_secret: str
) -> tuple[SyncStorageClient, SyncStorageClient]:
    """Two storage clients on one account, as a household has.

    They share a credential rather than each holding their own, which is a
    simplification the tokenserver would not make -- but every question here is
    about what the *storage* tier returns to a second reader, and two tokens
    would only mean two ways to spell the same uid.
    """
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    token = await tokenserver.token(
        grant.access_token, sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])
    )
    return (
        SyncStorageClient(http, token, secret=tokenserver_secret),
        SyncStorageClient(http, token, secret=tokenserver_secret),
    )


async def _write(storage: SyncStorageClient, collection: str, bso_id: str, payload: str) -> int:
    """Store one record and return the collection timestamp, in milliseconds."""
    response = await storage.put(
        f"/storage/{collection}/{bso_id}", json_body={"payload": payload}
    )
    assert response.status_code == 200, response.text
    return _as_milliseconds(response.headers["x-last-modified"])


def _as_milliseconds(seconds: str | float) -> int:
    """Sync timestamps are seconds with two decimals; the database holds them
    as whole hundredths of milliseconds, and `round` is what crosses that
    without a float's last bit deciding the answer."""
    return round(float(seconds) * 1000)


class MobileEngine:
    """`get_collection_request` and the two places `last_sync` is written.

    Upstream (`places/src/bookmark_sync/engine.rs`):

    * `get_collection_request(server_timestamp)` returns `None` when its stored
      `since` equals the `info/collections` value, and otherwise a request that
      is `.full().newer_than(since)`;
    * `apply()` stores that same `info/collections` value as the new `since` --
      *before* merging, so a record downloaded and then dropped is never asked
      for again.

    `skipped` records which branch the last `sync()` took, because "the phone
    never asked" and "the phone asked and got nothing" are different bugs with
    the same symptom.
    """

    def __init__(self, storage: SyncStorageClient, collection: str) -> None:
        self.storage = storage
        self.collection = collection
        self.since = 0
        self.skipped = False

    async def sync(self) -> list[dict[str, Any]]:
        collections, last_modified = await self.storage.info_collections()
        assert last_modified is not None, "sync15 fails hard on a 2xx with no X-Last-Modified"
        server = _as_milliseconds(collections.get(self.collection, 0))

        if self.since == server:
            self.skipped = True
            return []

        self.skipped = False
        response = await self.storage.get_collection(
            self.collection, full=True, newer=server_timestamp(self.since)
        )
        records = expect_ok(response)
        self.since = server
        return records


# --------------------------------------------------------------------------
# The report this module exists for.
# --------------------------------------------------------------------------


async def test_the_phone_sees_what_desktop_wrote_after_it_last_looked(pair) -> None:
    """Desktop writes, the phone syncs, desktop writes again, the phone syncs.

    The second sync is the one that matters: `newer=` is the phone's own
    high-water mark from the first, and the record it must come back with is
    the only one written since.  A server that answered the first sync
    correctly and the second one with an empty list would look, from the
    phone, exactly like the reported symptom.
    """
    desktop, phone = pair
    engine = MobileEngine(phone, "bookmarks")

    await _write(desktop, "bookmarks", "menu", "first")
    first = await engine.sync()
    assert not engine.skipped
    assert [record["id"] for record in first] == ["menu"]

    await _write(desktop, "bookmarks", "toolbar", "second")
    second = await engine.sync()
    assert not engine.skipped
    assert [record["id"] for record in second] == ["toolbar"]
    assert second[0]["payload"] == "second"


async def test_the_phone_skips_the_fetch_when_nothing_has_changed(pair) -> None:
    """And the skip is the client's rule, not an empty answer from us.

    Worth pinning because it is the trap in reading a trace: a sync with no
    `GET /storage/bookmarks` in it is not evidence that the server refused
    anything.
    """
    desktop, phone = pair
    engine = MobileEngine(phone, "bookmarks")

    await _write(desktop, "bookmarks", "menu", "first")
    assert [record["id"] for record in await engine.sync()] == ["menu"]

    assert await engine.sync() == []
    assert engine.skipped


async def test_the_phones_own_upload_does_not_come_back_to_it(pair) -> None:
    """The other half of the high-water mark, and the reason it is strict.

    `newer_than` assumes `modified > newer`.  If it were `>=` the phone would
    re-download every record it had just uploaded, on every sync, forever --
    which is not a data-loss bug and is exactly the kind that goes unnoticed.
    """
    desktop, phone = pair
    engine = MobileEngine(phone, "bookmarks")

    await _write(desktop, "bookmarks", "menu", "first")
    await engine.sync()

    await _write(phone, "bookmarks", "mobile", "from the phone")
    assert [record["id"] for record in await engine.sync()] == ["mobile"]
    assert await engine.sync() == []


# --------------------------------------------------------------------------
# The two spellings of one instant.
# --------------------------------------------------------------------------


async def test_the_timestamp_a_write_returns_excludes_that_write(pair) -> None:
    """`X-Last-Modified` fed straight back as `newer=` selects what came next.

    Both sides of the boundary are asserted, and deliberately: a `?newer=` that
    drifted a hundredth *up* would hide a record from a phone forever, which is
    the shape of the report this module was written for, and one that drifted
    *down* would re-send it on every sync. Only pinning the exact hundredth
    catches both, and neither depends on how fast the two writes ran.
    """
    desktop, phone = pair

    first = await _write(desktop, "bookmarks", "menu", "first")
    await _write(desktop, "bookmarks", "toolbar", "second")

    at = await phone.get_collection("bookmarks", newer=server_timestamp(first))
    assert [record["id"] for record in expect_ok(at)] == ["toolbar"]

    just_before = await phone.get_collection("bookmarks", newer=server_timestamp(first - 10))
    assert sorted(record["id"] for record in expect_ok(just_before)) == ["menu", "toolbar"]


@pytest.mark.parametrize("shift", [-10, 0, 10])
async def test_both_spellings_of_one_instant_select_the_same_records(pair, shift: int) -> None:
    """`%.2f` and the Rust client's shortest form are the same moment.

    `X-Last-Modified` is always two decimals; `ServerTimestamp`'s `Display` is
    `self.0 as f64 / 1000.0`, which drops a trailing zero -- so one instant has
    two spellings on the wire and only one of them has ever been tested.  The
    shifts straddle a record's own timestamp, so the two queries have to agree
    about a boundary rather than agreeing that everything is in the past.
    """
    desktop, phone = pair

    first = await _write(desktop, "bookmarks", "menu", "first")
    await _write(desktop, "bookmarks", "toolbar", "second")
    instant = first + shift

    fixed = await phone.get_collection("bookmarks", newer=f"{instant / 1000:.2f}")
    shortest = await phone.get_collection("bookmarks", newer=server_timestamp(instant))
    assert [record["id"] for record in expect_ok(fixed)] == [
        record["id"] for record in expect_ok(shortest)
    ]


# --------------------------------------------------------------------------
# `sort=none`, which upstream accepts and fxa-lite used to refuse.
# --------------------------------------------------------------------------


async def test_sort_none_is_accepted_and_means_no_order(pair) -> None:
    """`Sorting::None` is upstream's *default* variant, spelled on the wire.

    `syncstorage-db-common`'s enum carries `#[serde(rename_all = "lowercase")]`,
    so `?sort=none` parses there, and `db_impl.rs` then matches it alongside
    `Sorting::Newest` in `get_bsos` and lets it fall through the `_` arm in
    `get_bso_ids`.  Refusing it was a divergence with no argument behind it.
    """
    desktop, phone = pair

    await _write(desktop, "bookmarks", "menu", "first")
    await _write(desktop, "bookmarks", "toolbar", "second")

    explicit = await phone.get_collection("bookmarks", sort="none")
    absent = await phone.get_collection("bookmarks")
    assert explicit.status_code == 200, explicit.text
    assert expect_ok(explicit) == expect_ok(absent)


async def test_an_unrecognised_sort_is_still_refused(pair) -> None:
    """The fix widens the vocabulary by one word, not to anything."""
    _, phone = pair
    response = await phone.get_collection("bookmarks", sort="sideways")
    assert response.status_code == 400
