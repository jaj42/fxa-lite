"""The storage layer's own arithmetic, away from HTTP.

Pagination and timestamp quantization are where Sync 1.5 hides its subtlety:
an offset token that skips one row too few serves a record twice, one that
skips one too many loses it silently, and a timestamp rounded the wrong way
makes `?newer=` disagree with the `X-Last-Modified` that produced it. Upstream
has known answers for the first; the rest are pinned against the reference
implementations they were transcribed from.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from fxa_lite.db import Account, Database, open_database
from fxa_lite.syncstorage.store import (
    BATCH_LIFETIME_MS,
    DEFAULT_BSO_TTL,
    MAX_TTL,
    BatchNotFound,
    Bso,
    BsoNotFound,
    BsoQuery,
    CollectionNotFound,
    ConflictError,
    Offset,
    SyncStore,
    decode_batch_id,
    encode_batch_id,
    encode_next_offset,
    quantize,
    timestamp_header,
    timestamp_json,
)
from vectors import load

OFFSETS = load("hawk")["offsets"]["cases"]

NOW = 1_700_000_000_000


@pytest.fixture
def store() -> Iterator[SyncStore]:
    db = open_database(":memory:")
    uid = _provision(db)
    try:
        yield SyncStore(db, uid, NOW)
    finally:
        db.close()


def _provision(db: Database, *, fxa_uid: str = "a" * 32) -> int:
    """A Sync uid needs an account and a `sync_users` row behind it."""
    db.create_account(
        Account(
            uid=fxa_uid,
            email=f"{fxa_uid[:4]}@example.com",
            normalized_email=f"{fxa_uid[:4]}@example.com",
            email_code="0" * 32,
            ka="1" * 64,
            wrap_wrap_kb="2" * 64,
            auth_salt="3" * 64,
            verify_hash="4" * 64,
            verifier_version=1,
            verifier_set_at=NOW,
            created_at=NOW,
            keys_changed_at=NOW,
            profile_changed_at=NOW,
        )
    )
    return db.create_sync_user(
        fxa_uid=fxa_uid,
        client_state="5" * 32,
        generation=NOW,
        keys_changed_at=NOW,
        created_at=NOW,
    ).uid


def read(store: SyncStore, collection: str, bso_id: str) -> Bso:
    """`get_bso`, asserting the record exists — every caller below requires it."""
    record = store.get_bso(collection, bso_id)
    assert record is not None
    return record


# -- timestamps -------------------------------------------------------------


@pytest.mark.parametrize(
    "milliseconds,expected", [(0, 0), (9, 0), (10, 10), (1234, 1230), (1239, 1230)]
)
def test_quantize_truncates_to_a_hundredth_of_a_second(milliseconds, expected):
    """`SyncTimestamp::from_milliseconds`. Truncation, never rounding: a
    timestamp that rounded *up* would name an instant that has not happened."""
    assert quantize(milliseconds) == expected


def test_the_header_always_carries_two_decimals():
    assert timestamp_header(0) == "0.00"
    assert timestamp_header(1_591_142_320_340) == "1591142320.34"
    assert timestamp_header(1_591_142_320_100) == "1591142320.10"


def test_the_json_form_is_the_same_value():
    assert timestamp_json(1_591_142_320_340) == 1591142320.34
    assert timestamp_json(0) == 0


# -- offsets ----------------------------------------------------------------


@pytest.mark.parametrize("case", OFFSETS, ids=[c["name"] for c in OFFSETS])
def test_encode_next_offset_matches_the_reference(case):
    assert (
        encode_next_offset(
            case["sort"], case["prev_offset"], case["prev_timestamp"], case["modified"]
        )
        == case["expected"]
    )


@pytest.mark.parametrize(
    "text,timestamp,offset",
    [("42", None, 42), ("1234:7", 1230, 7), ("0:0", 0, 0)],
)
def test_offset_round_trips(text, timestamp, offset):
    parsed = Offset.parse(text)
    assert (parsed.timestamp, parsed.offset) == (timestamp, offset)
    assert str(Offset(timestamp=timestamp, offset=offset)) == (
        text if ":" not in text else f"{timestamp}:{offset}"
    )


@pytest.mark.parametrize("text", ["-1", "1:-1", "abc", "", "1:2:3"])
def test_malformed_offsets_are_rejected(text):
    with pytest.raises(ValueError):
        Offset.parse(text)


# -- batch ids --------------------------------------------------------------


def test_batch_ids_round_trip():
    assert decode_batch_id(encode_batch_id(1234)) == 1234


def test_a_bare_decimal_batch_id_still_decodes():
    """The old Python server handed these out; a client may still hold one."""
    assert decode_batch_id("1536198976921") == 1536198976921


def test_an_undecodable_batch_id_is_not_found():
    with pytest.raises(BatchNotFound):
        decode_batch_id("nonsense!!")


# -- records ----------------------------------------------------------------


def test_a_stored_record_reads_back(store):
    store.put_bso("bookmarks", "abc", payload="hello", sortindex=3)
    record = read(store, "bookmarks", "abc")
    assert (record.id, record.payload, record.sortindex) == ("abc", "hello", 3)
    assert record.modified == NOW
    assert record.expiry == NOW + DEFAULT_BSO_TTL * 1000


def test_a_partial_update_leaves_the_other_fields_alone(store):
    store.put_bso("bookmarks", "abc", payload="hello", sortindex=3)
    later = SyncStore(store.db, store.uid, NOW + 1000)
    later.put_bso("bookmarks", "abc", sortindex=9)
    record = read(later, "bookmarks", "abc")
    assert (record.payload, record.sortindex) == ("hello", 9)
    assert record.modified == NOW + 1000


def test_an_update_with_nothing_to_say_does_not_move_modified(store):
    """Only a `ttl` — nothing the client can see changed, so `modified` holds.

    Upstream's conditional `ON DUPLICATE KEY UPDATE` has exactly this shape,
    and a client that polls `?newer=` would otherwise re-fetch a record whose
    contents are identical.
    """
    store.put_bso("bookmarks", "abc", payload="hello")
    later = SyncStore(store.db, store.uid, NOW + 1000)
    later.put_bso("bookmarks", "abc", ttl=60)
    record = read(later, "bookmarks", "abc")
    assert record.modified == NOW
    assert record.expiry == NOW + 1000 + 60_000


def test_an_expired_record_is_invisible(store):
    store.put_bso("bookmarks", "gone", payload="x", ttl=10)
    later = SyncStore(store.db, store.uid, NOW + 11_000)
    assert later.get_bso("bookmarks", "gone") is None
    assert later.collection_counts() == {}
    assert later.get_bsos("bookmarks", BsoQuery()).items == []


def test_a_write_that_cannot_advance_the_timestamp_conflicts(store):
    store.put_bso("bookmarks", "abc", payload="x")
    with pytest.raises(ConflictError):
        store.check_write(store.collection_id("bookmarks"))


def test_deleting_a_collection_moves_the_storage_timestamp(store):
    store.put_bso("bookmarks", "abc", payload="x")
    later = SyncStore(store.db, store.uid, NOW + 1000)
    assert later.delete_collection("bookmarks") == NOW + 1000
    assert later.collection_timestamps() == {}
    # The tombstone is what keeps the storage timestamp moving with nothing
    # left to carry it.
    assert later.storage_timestamp() == NOW + 1000


def test_deleting_a_collection_that_is_not_there_is_not_found(store):
    with pytest.raises(CollectionNotFound):
        store.delete_collection("bookmarks")


def test_deleting_a_record_that_is_not_there_is_not_found(store):
    store.put_bso("bookmarks", "abc", payload="x")
    later = SyncStore(store.db, store.uid, NOW + 1000)
    with pytest.raises(BsoNotFound):
        later.delete_bso("bookmarks", "nope")


def test_collection_usage_counts_payload_bytes(store):
    store.put_bso("bookmarks", "a", payload="12345")
    store.put_bso("bookmarks", "b", payload="123")
    assert store.collection_usage() == {"bookmarks": 8}
    assert store.storage_usage() == 8


# -- pagination -------------------------------------------------------------


def _fill(store: SyncStore, count: int) -> None:
    """Records one hundredth of a second apart, oldest first."""
    for index in range(count):
        writer = SyncStore(store.db, store.uid, NOW + index * 10)
        writer.put_bso("bookmarks", f"id{index:02d}", payload=f"p{index}")


def test_a_limited_read_hands_back_an_offset_that_continues_it(store):
    _fill(store, 5)
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    first = reader.get_bsos("bookmarks", BsoQuery(sort="newest", limit=2))
    assert [item.id for item in first.items] == ["id04", "id03"]
    assert first.offset is not None

    second = reader.get_bsos(
        "bookmarks", BsoQuery(sort="newest", limit=2, offset=Offset.parse(first.offset))
    )
    assert [item.id for item in second.items] == ["id02", "id01"]


def test_pagination_returns_every_record_exactly_once(store):
    _fill(store, 7)
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    seen: list[str] = []
    offset = None
    for _ in range(10):
        page = reader.get_bsos(
            "bookmarks",
            BsoQuery(sort="oldest", limit=2, offset=Offset.parse(offset) if offset else None),
        )
        seen.extend(item.id for item in page.items)
        offset = page.offset
        if offset is None:
            break
    assert seen == [f"id{i:02d}" for i in range(7)]


def test_records_sharing_a_timestamp_still_paginate(store):
    """The whole reason the offset token carries a skip count."""
    for index in range(5):
        store.put_bso("bookmarks", f"id{index}", payload="x", touch_collection=False)
    store.update_collection(store.collection_id("bookmarks"))
    reader = SyncStore(store.db, store.uid, NOW + 10_000)

    seen: list[str] = []
    offset = None
    for _ in range(10):
        page = reader.get_bsos(
            "bookmarks",
            BsoQuery(sort="newest", limit=2, offset=Offset.parse(offset) if offset else None),
        )
        seen.extend(item.id for item in page.items)
        offset = page.offset
        if offset is None:
            break
    assert sorted(seen) == [f"id{i}" for i in range(5)]
    assert len(seen) == len(set(seen))


def test_ids_pagination_uses_a_plain_row_count(store):
    """`get_bso_ids` upstream returns a bare number, not a timestamp token."""
    _fill(store, 5)
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    page = reader.get_bsos("bookmarks", BsoQuery(sort="newest", limit=2), full=False)
    assert page.items == ["id04", "id03"]
    assert page.offset == "2"


def test_limit_zero_asks_whether_there_is_anything(store):
    _fill(store, 3)
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    page = reader.get_bsos("bookmarks", BsoQuery(limit=0))
    assert page.items == []
    assert page.offset == "0"


def test_newer_and_older_bound_the_window(store):
    _fill(store, 5)
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    page = reader.get_bsos(
        "bookmarks", BsoQuery(newer=NOW + 10, older=NOW + 40, sort="oldest")
    )
    assert [item.id for item in page.items] == ["id02", "id03"]


def test_index_sort_orders_by_sortindex(store):
    for index, weight in enumerate([5, 1, 9]):
        store.put_bso("bookmarks", f"id{index}", payload="x", sortindex=weight,
                      touch_collection=False)
    store.update_collection(store.collection_id("bookmarks"))
    reader = SyncStore(store.db, store.uid, NOW + 10_000)
    page = reader.get_bsos("bookmarks", BsoQuery(sort="index"))
    assert [item.sortindex for item in page.items] == [9, 5, 1]


# -- batches ----------------------------------------------------------------


class _Item:
    def __init__(self, id, payload=None, sortindex=None, ttl=None):
        self.id, self.payload, self.sortindex, self.ttl = id, payload, sortindex, ttl


def test_a_batch_is_invisible_until_it_commits(store):
    batch = store.create_batch("bookmarks")
    store.append_to_batch("bookmarks", batch, [_Item("a", payload="one")])
    assert store.get_bso("bookmarks", "a") is None

    later = SyncStore(store.db, store.uid, NOW + 1000)
    assert later.commit_batch("bookmarks", batch) == NOW + 1000
    record = read(later, "bookmarks", "a")
    assert record.payload == "one"
    assert record.modified == NOW + 1000


def test_every_record_in_a_batch_lands_at_one_instant(store):
    batch = store.create_batch("bookmarks")
    store.append_to_batch("bookmarks", batch, [_Item("a", payload="1")])
    store.append_to_batch("bookmarks", batch, [_Item("b", payload="2")])
    later = SyncStore(store.db, store.uid, NOW + 1000)
    later.commit_batch("bookmarks", batch)
    assert {r.modified for r in later.get_bsos("bookmarks", BsoQuery()).items} == {NOW + 1000}


def test_a_repeated_id_in_a_batch_replaces_only_itself(store):
    """Upstream's `do_append` forgets to filter on the id and rewrites the lot."""
    batch = store.create_batch("bookmarks")
    store.append_to_batch(
        "bookmarks", batch, [_Item("a", payload="one"), _Item("b", payload="two")]
    )
    store.append_to_batch("bookmarks", batch, [_Item("a", payload="ONE")])
    later = SyncStore(store.db, store.uid, NOW + 1000)
    later.commit_batch("bookmarks", batch)
    assert read(later, "bookmarks", "a").payload == "ONE"
    assert read(later, "bookmarks", "b").payload == "two"


def test_a_batch_field_left_unset_does_not_blank_an_existing_record(store):
    store.put_bso("bookmarks", "a", payload="keep", sortindex=4)
    later = SyncStore(store.db, store.uid, NOW + 1000)
    batch = later.create_batch("bookmarks")
    later.append_to_batch("bookmarks", batch, [_Item("a", sortindex=7)])
    later.commit_batch("bookmarks", batch)
    record = read(later, "bookmarks", "a")
    assert (record.payload, record.sortindex) == ("keep", 7)


def test_a_new_batch_record_with_no_ttl_gets_the_absolute_maximum(store):
    """`batch_commit.sql` uses `MAX_TTL` as an instant, not as a duration —
    a different "forever" from the un-batched path's, and reproduced as such."""
    batch = store.create_batch("bookmarks")
    store.append_to_batch("bookmarks", batch, [_Item("a", payload="x")])
    store.commit_batch("bookmarks", batch)
    assert read(store, "bookmarks", "a").expiry == MAX_TTL * 1000


def test_an_expired_batch_is_no_longer_valid(store):
    batch = store.create_batch("bookmarks")
    stale = SyncStore(store.db, store.uid, NOW + BATCH_LIFETIME_MS + 10)
    assert not stale.validate_batch("bookmarks", batch)


def test_a_batch_belongs_to_one_collection(store):
    batch = store.create_batch("bookmarks")
    assert store.validate_batch("bookmarks", batch)
    assert not store.validate_batch("history", batch)


def test_wiping_storage_takes_open_batches_with_it(store):
    """Upstream leaves them, and a later commit resurrects what the wipe removed."""
    batch = store.create_batch("bookmarks")
    store.append_to_batch("bookmarks", batch, [_Item("a", payload="x")])
    store.delete_storage()
    assert not store.validate_batch("bookmarks", batch)


def test_two_users_do_not_see_each_others_records(store):
    other = SyncStore(store.db, _provision(store.db, fxa_uid="b" * 32), NOW)
    store.put_bso("bookmarks", "mine", payload="x")
    assert other.get_bsos("bookmarks", BsoQuery()).items == []
    assert other.collection_timestamps() == {}
