"""Sync 1.5 storage over HTTP, driven by a client that signs its own requests.

Every request here carries a real HAWK signature built by
`conformance/client.py` from the tokenserver's response — an implementation
written out from the HAWK specification rather than shared with
`fxa_lite.syncstorage.hawk`, so a mistake in either shows up as a failure
instead of as two modules agreeing.

The fixture is the whole stack: password typed, `kB` recovered, OAuth token
issued, tokenserver asked, storage credential in hand. That is deliberate —
the point of the phase is that the five tiers compose, and a storage test that
started from a hand-made token would not prove it.
"""

from __future__ import annotations

import json
import time

import pytest

from conformance.client import (
    OLDSYNC_SCOPE,
    AuthClient,
    SyncStorageClient,
    TokenserverClient,
    hawk_storage_header,
    sync_key_id,
)
from conftest import EMAIL, PASSWORD
from fxa_lite import syncstorage
from fxa_lite.syncstorage.models import LIMITS


@pytest.fixture
async def storage(
    bearer_client: AuthClient, tokenserver: TokenserverClient, http, tokenserver_secret: str
) -> SyncStorageClient:
    """A signed-in account with a storage credential, from the password up."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    token = await tokenserver.token(
        grant.access_token, sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])
    )
    return SyncStorageClient(http, token, secret=tokenserver_secret)


async def _put(storage: SyncStorageClient, collection: str, bso_id: str, **body):
    response = await storage.put(f"/storage/{collection}/{bso_id}", json_body=body)
    assert response.status_code == 200, response.text
    return response


# --------------------------------------------------------------------------
# The round trip the whole project exists for.
# --------------------------------------------------------------------------


async def test_the_whole_stack_composes(
    bearer_client: AuthClient, tokenserver: TokenserverClient, http, tokenserver_secret: str
) -> None:
    """Password to stored record, through every tier, in one test.

    Sign in, unwrap `kB`, derive the oldsync scoped key, trade it for an access
    token, exchange that for a storage credential, sign a request with the key
    the tokenserver derived, and read the record back. Each tier has its own
    tests; this is the one that would fail if any two of them disagreed about
    what they hand each other.
    """
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    key_id = sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])
    token = await tokenserver.token(grant.access_token, key_id)

    # The credential names the same key generation the client just derived.
    assert token["api_endpoint"].endswith(f"/1.5/{token['uid']}")
    client = SyncStorageClient(http, token, secret=tokenserver_secret)

    written = await client.put(
        "/storage/bookmarks/record", json_body={"payload": "ciphertext"}
    )
    assert written.status_code == 200
    read = await client.get("/storage/bookmarks/record")
    assert read.json()["payload"] == "ciphertext"
    assert read.headers["X-Last-Modified"] == written.headers["X-Last-Modified"]


async def test_a_record_written_reads_back(storage: SyncStorageClient) -> None:
    await _put(storage, "bookmarks", "abc", payload="encrypted", sortindex=5)
    response = await storage.get("/storage/bookmarks/abc")
    assert response.status_code == 200
    assert response.json() == {
        "id": "abc",
        "modified": pytest.approx(float(response.headers["X-Last-Modified"])),
        "payload": "encrypted",
        "sortindex": 5,
    }


async def test_the_endpoint_appears_in_info_collections(storage: SyncStorageClient) -> None:
    put = await _put(storage, "bookmarks", "abc", payload="x")
    response = await storage.get("/info/collections")
    assert response.status_code == 200
    assert response.json() == {"bookmarks": float(put.headers["X-Last-Modified"])}
    assert response.headers["X-Weave-Records"] == "1"


async def test_a_collection_reads_back_as_ids_then_records(
    storage: SyncStorageClient,
) -> None:
    await _put(storage, "bookmarks", "one", payload="1")
    await _put(storage, "bookmarks", "two", payload="2")

    ids = await storage.get("/storage/bookmarks")
    assert sorted(ids.json()) == ["one", "two"]
    assert ids.headers["X-Weave-Records"] == "2"

    full = await storage.get("/storage/bookmarks", params={"full": ""})
    assert sorted(item["payload"] for item in full.json()) == ["1", "2"]


async def test_a_collection_nobody_has_written_to_is_empty_not_missing(
    storage: SyncStorageClient,
) -> None:
    """A first sync asks for every engine before any of them can exist."""
    response = await storage.get("/storage/bookmarks")
    assert response.status_code == 200
    assert response.json() == []


async def test_post_stores_many_and_reports_each(storage: SyncStorageClient) -> None:
    response = await storage.post(
        "/storage/bookmarks",
        json_body=[
            {"id": "a", "payload": "1"},
            {"id": "b", "payload": "2"},
            {"id": "c", "payload": "3", "sortindex": "not a number"},
        ],
    )
    assert response.status_code == 200
    body = response.json()
    assert sorted(body["success"]) == ["a", "b"]
    # One malformed record does not fail the request: the other two are stored
    # and the client is told which one to fix.
    assert list(body["failed"]) == ["c"]
    assert body["modified"] == float(response.headers["X-Last-Modified"])


async def test_records_from_one_post_share_a_timestamp(storage: SyncStorageClient) -> None:
    await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": f"id{i}", "payload": str(i)} for i in range(5)],
    )
    full = await storage.get("/storage/bookmarks", params={"full": ""})
    assert len({item["modified"] for item in full.json()}) == 1


async def test_a_deleted_record_is_gone(storage: SyncStorageClient) -> None:
    await _put(storage, "bookmarks", "abc", payload="x")
    deleted = await storage.delete("/storage/bookmarks/abc")
    assert deleted.status_code == 200
    assert (await storage.get("/storage/bookmarks/abc")).status_code == 404


async def test_deleting_all_storage_empties_it(storage: SyncStorageClient) -> None:
    await _put(storage, "bookmarks", "abc", payload="x")
    assert (await storage.delete("")).status_code == 200
    assert (await storage.get("/info/collections")).json() == {}


async def test_the_legacy_delete_storage_spelling_works_too(
    storage: SyncStorageClient,
) -> None:
    await _put(storage, "bookmarks", "abc", payload="x")
    assert (await storage.delete("/storage")).status_code == 200
    assert (await storage.get("/info/collections")).json() == {}


# --------------------------------------------------------------------------
# Authentication.
# --------------------------------------------------------------------------


async def test_an_unsigned_request_is_refused(storage: SyncStorageClient, http) -> None:
    response = await http.get(f"{storage.prefix}/info/collections")
    assert response.status_code == 401
    # Sync's entire error vocabulary is one integer.
    assert response.json() == 0


async def test_a_request_signed_with_the_wrong_key_is_refused(
    storage: SyncStorageClient, http
) -> None:
    """The key is derived, never sent — holding the token id is not enough."""
    path = f"{storage.prefix}/info/collections"
    header = hawk_storage_header(
        token_id=storage.token_id,
        key="not-the-derived-key",
        method="GET",
        resource=path,
        host=storage.host,
        port=storage.port,
    )
    response = await http.get(path, headers={"authorization": header})
    assert response.status_code == 401


async def test_a_signature_for_another_path_does_not_authorize_this_one(
    storage: SyncStorageClient, http
) -> None:
    """A GET of one collection must not authorize a DELETE of the storage."""
    header = hawk_storage_header(
        token_id=storage.token_id,
        key=storage.key,
        method="GET",
        resource=f"{storage.prefix}/storage/bookmarks",
        host=storage.host,
        port=storage.port,
    )
    response = await http.delete(storage.prefix, headers={"authorization": header})
    assert response.status_code == 401


async def test_a_tampered_body_is_refused(storage: SyncStorageClient, http) -> None:
    """The payload hash the client sent is checked against the body received."""
    path = f"{storage.prefix}/storage/bookmarks/abc"
    body = json.dumps({"payload": "mine"}).encode()
    header = hawk_storage_header(
        token_id=storage.token_id,
        key=storage.key,
        method="PUT",
        resource=path,
        host=storage.host,
        port=storage.port,
        body=body,
        content_type="application/json",
    )
    response = await http.put(
        path,
        content=json.dumps({"payload": "theirs"}).encode(),
        headers={"authorization": header, "content-type": "application/json"},
    )
    assert response.status_code == 401


async def test_an_id_that_needs_escaping_round_trips(storage: SyncStorageClient) -> None:
    """The MAC covers the target as sent, so an escaped id verifies and routes.

    `BSO_ID_RE` is upstream's, and admits any printable ASCII — a space, a
    percent sign, a hash. None of those survive a URL untouched, so this is
    the case that used to fail: the client signs `a%20b%25c%23d`, and a server
    that verified against the decoded path would be checking a string the
    client never signed.
    """
    escaped = "a%20b%25c%23d"
    decoded = "a b%c#d"

    written = await storage.put(
        f"/storage/bookmarks/{escaped}", json_body={"payload": "kept"}
    )
    assert written.status_code == 200

    read = await storage.get(f"/storage/bookmarks/{escaped}")
    assert read.status_code == 200
    assert read.json()["payload"] == "kept"
    # Stored under the decoded id, which is the id the client believes it used.
    assert read.json()["id"] == decoded

    listed = await storage.get("/storage/bookmarks")
    assert listed.json() == [decoded]

    gone = await storage.delete(f"/storage/bookmarks/{escaped}")
    assert gone.status_code == 200
    assert (await storage.get("/storage/bookmarks")).json() == []


async def test_a_signature_over_the_decoded_target_is_refused(
    storage: SyncStorageClient, http
) -> None:
    """The other direction: signing what the escapes *mean* is not signing them.

    This is the assertion that pins the fix rather than the behaviour around
    it. Upstream reads `uri.path_and_query()`, which actix leaves encoded; if
    this server ever went back to `request.url.path` the test above would still
    pass — both halves would decode — and only this one would fail.
    """
    escaped = f"{storage.prefix}/storage/bookmarks/a%20b"
    header = hawk_storage_header(
        token_id=storage.token_id,
        key=storage.key,
        method="GET",
        resource=f"{storage.prefix}/storage/bookmarks/a b",
        host=storage.host,
        port=storage.port,
    )
    response = await http.get(escaped, headers={"authorization": header})
    assert response.status_code == 401


async def test_an_id_containing_a_slash_has_no_url_but_is_not_lost(
    storage: SyncStorageClient,
) -> None:
    """`bso-id-with-a-slash-unroutable`, stated as the two halves it has.

    Upstream splits the raw path and decodes the last element, so `%2F` is an
    ordinary character there. Starlette matches on the path the server already
    decoded, so the same target is one segment too long and nothing routes.
    What the divergence must not cost is the record itself: it goes in through
    the body and comes back through the query string.
    """
    unroutable = "folder/child"

    stored = await storage.post(
        "/storage/bookmarks", json_body=[{"id": unroutable, "payload": "kept"}]
    )
    assert stored.json()["success"] == [unroutable]

    listed = await storage.get("/storage/bookmarks", params={"ids": unroutable})
    assert listed.json() == [unroutable]
    full = await storage.get(
        "/storage/bookmarks", params={"ids": unroutable, "full": "1"}
    )
    assert full.json()[0]["payload"] == "kept"

    # The per-record URL is the half that cannot be spelled.
    assert (await storage.get("/storage/bookmarks/folder%2Fchild")).status_code == 404

    removed = await storage.delete("/storage/bookmarks", params={"ids": unroutable})
    assert removed.status_code == 200
    assert (await storage.get("/storage/bookmarks")).json() == []


async def test_a_token_cannot_be_spent_against_another_uid(
    storage: SyncStorageClient, http
) -> None:
    """The path selects the data; the token has to agree with it."""
    other = f"{storage.prefix.rsplit('/', 1)[0]}/{storage.uid + 1}"
    header = hawk_storage_header(
        token_id=storage.token_id,
        key=storage.key,
        method="GET",
        resource=f"{other}/info/collections",
        host=storage.host,
        port=storage.port,
    )
    response = await http.get(
        f"{other}/info/collections", headers={"authorization": header}
    )
    assert response.status_code == 401


async def test_configuration_needs_no_credential(storage: SyncStorageClient, http) -> None:
    """A client needs the limits before it can decide how to split an upload."""
    response = await http.get(f"{storage.prefix}/info/configuration")
    assert response.status_code == 200
    assert response.json() == LIMITS.as_json()
    assert response.headers["X-Last-Modified"] == "0.00"


# --------------------------------------------------------------------------
# Conditional requests.
# --------------------------------------------------------------------------


async def test_if_modified_since_answers_304_when_nothing_changed(
    storage: SyncStorageClient,
) -> None:
    put = await _put(storage, "bookmarks", "abc", payload="x")
    stamp = put.headers["X-Last-Modified"]
    response = await storage.get(
        "/storage/bookmarks", headers={"X-If-Modified-Since": stamp}
    )
    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["X-Last-Modified"] == stamp


async def test_if_unmodified_since_refuses_a_write_over_a_newer_record(
    storage: SyncStorageClient,
) -> None:
    """The header exists so two devices editing one record notice each other."""
    await _put(storage, "bookmarks", "abc", payload="first")
    response = await storage.put(
        "/storage/bookmarks/abc",
        json_body={"payload": "second"},
        headers={"X-If-Unmodified-Since": "1.00"},
    )
    assert response.status_code == 412
    assert (await storage.get("/storage/bookmarks/abc")).json()["payload"] == "first"


async def test_both_precondition_headers_at_once_is_an_error(
    storage: SyncStorageClient,
) -> None:
    response = await storage.get(
        "/storage/bookmarks",
        headers={"X-If-Modified-Since": "1.00", "X-If-Unmodified-Since": "2.00"},
    )
    assert response.status_code == 400


async def test_every_response_carries_a_weave_timestamp(
    storage: SyncStorageClient, http
) -> None:
    """Including the refusals: a skewed client learns the time from the 401."""
    response = await storage.get("/info/collections")
    assert float(response.headers["X-Weave-Timestamp"]) > 0
    refused = await http.get(f"{storage.prefix}/info/collections")
    assert refused.status_code == 401
    assert float(refused.headers["X-Weave-Timestamp"]) > 0


# --------------------------------------------------------------------------
# Batches.
# --------------------------------------------------------------------------


async def test_a_batch_is_invisible_until_committed(storage: SyncStorageClient) -> None:
    opened = await storage.post(
        "/storage/bookmarks",
        params={"batch": "true"},
        json_body=[{"id": "a", "payload": "1"}],
    )
    assert opened.status_code == 202
    batch = opened.json()["batch"]
    assert (await storage.get("/storage/bookmarks")).json() == []

    committed = await storage.post(
        "/storage/bookmarks", params={"batch": batch, "commit": "true"}, json_body=[]
    )
    assert committed.status_code == 200
    assert (await storage.get("/storage/bookmarks")).json() == ["a"]


async def test_a_batch_accumulates_across_several_posts(
    storage: SyncStorageClient,
) -> None:
    opened = await storage.post(
        "/storage/bookmarks", params={"batch": "true"}, json_body=[{"id": "a", "payload": "1"}]
    )
    batch = opened.json()["batch"]
    await storage.post(
        "/storage/bookmarks", params={"batch": batch}, json_body=[{"id": "b", "payload": "2"}]
    )
    await storage.post(
        "/storage/bookmarks", params={"batch": batch, "commit": "true"}, json_body=[]
    )
    full = await storage.get("/storage/bookmarks", params={"full": ""})
    records = {item["id"]: item for item in full.json()}
    assert sorted(records) == ["a", "b"]
    # The whole batch is one instant, however many requests carried it.
    assert len({item["modified"] for item in records.values()}) == 1


async def test_a_commit_may_carry_records_of_its_own(
    storage: SyncStorageClient,
) -> None:
    """The shape every Firefox history upload actually has.

    A client is not supposed to send records with the commit, and Firefox
    sends them every time. They are written after the batch lands, at the same
    instant — which used to make the request conflict with the timestamp its
    own commit had just set, and answer 503 to a perfectly good upload.

    `retry_on_conflict=False` because the client's retry is exactly what hid
    this: the second attempt falls in a later hundredth and succeeds, so the
    only trace of the bug in a passing test run was that it took two round
    trips.
    """
    opened = await storage.post(
        "/storage/history",
        params={"batch": "true"},
        json_body=[{"id": "staged", "payload": "1"}],
        retry_on_conflict=False,
    )
    batch = opened.json()["batch"]

    committed = await storage.post(
        "/storage/history",
        params={"batch": batch, "commit": "true"},
        json_body=[{"id": "carried", "payload": "2"}],
        retry_on_conflict=False,
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["success"] == ["carried"]

    full = await storage.get("/storage/history", params={"full": ""})
    records = {item["id"]: item for item in full.json()}
    assert sorted(records) == ["carried", "staged"]
    # Staged and carried alike land at the one instant the commit defines.
    assert len({item["modified"] for item in records.values()}) == 1


async def test_a_commit_carrying_a_staged_id_takes_the_later_copy(
    storage: SyncStorageClient,
) -> None:
    """Written *after* the batch, so the copy sent with the commit wins."""
    opened = await storage.post(
        "/storage/history",
        params={"batch": "true"},
        json_body=[{"id": "a", "payload": "staged"}],
        retry_on_conflict=False,
    )
    batch = opened.json()["batch"]
    await storage.post(
        "/storage/history",
        params={"batch": batch, "commit": "true"},
        json_body=[{"id": "a", "payload": "carried"}],
        retry_on_conflict=False,
    )
    full = await storage.get("/storage/history", params={"full": ""})
    assert [item["payload"] for item in full.json()] == ["carried"]


async def test_batch_and_commit_together_is_just_a_post(
    storage: SyncStorageClient,
) -> None:
    response = await storage.post(
        "/storage/bookmarks",
        params={"batch": "true", "commit": "true"},
        json_body=[{"id": "a", "payload": "1"}],
    )
    assert response.status_code == 200
    assert "batch" not in response.json()
    assert (await storage.get("/storage/bookmarks")).json() == ["a"]


async def test_an_unknown_batch_is_a_bad_request(storage: SyncStorageClient) -> None:
    response = await storage.post(
        "/storage/bookmarks",
        params={"batch": "MTIz", "commit": "true"},
        json_body=[],
    )
    assert response.status_code == 400


async def test_commit_without_a_batch_is_an_error(storage: SyncStorageClient) -> None:
    response = await storage.post(
        "/storage/bookmarks", params={"commit": "true"}, json_body=[]
    )
    assert response.status_code == 400


# --------------------------------------------------------------------------
# Validation.
# --------------------------------------------------------------------------


async def test_a_collection_name_that_cannot_exist_is_a_404(
    storage: SyncStorageClient,
) -> None:
    response = await storage.get("/storage/not a collection")
    assert response.status_code == 404


async def test_a_body_that_is_not_json_is_an_invalid_wbo(
    storage: SyncStorageClient,
) -> None:
    response = await storage.put(
        "/storage/bookmarks/abc", content=b"{not json", content_type="application/json"
    )
    assert response.status_code == 400
    assert response.json() == 8


async def test_an_unacceptable_content_type_is_refused(
    storage: SyncStorageClient,
) -> None:
    response = await storage.put(
        "/storage/bookmarks/abc",
        content=b'{"payload":"x"}',
        content_type="application/xml",
    )
    assert response.status_code == 415


async def test_a_duplicated_id_in_a_post_fails_the_request(
    storage: SyncStorageClient,
) -> None:
    """Two records claiming one id means the server cannot tell what was meant."""
    response = await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": "a", "payload": "1"}, {"id": "a", "payload": "2"}],
    )
    assert response.status_code == 400


async def test_a_known_bad_crypto_payload_is_refused(storage: SyncStorageClient) -> None:
    """In `crypto` a broken record costs every device the collection, not one."""
    response = await storage.put(
        "/storage/crypto/keys",
        json_body={"payload": '{"IV": "AAAAAAAAAAAAAAAAAAAAAA==", "ciphertext": "x"}'},
    )
    assert response.status_code == 400


async def test_the_same_payload_is_fine_anywhere_else(storage: SyncStorageClient) -> None:
    response = await storage.put(
        "/storage/bookmarks/keys",
        json_body={"payload": '{"IV": "AAAAAAAAAAAAAAAAAAAAAA==", "ciphertext": "x"}'},
    )
    assert response.status_code == 200


async def test_an_announced_upload_over_the_limit_is_refused_early(
    storage: SyncStorageClient,
) -> None:
    """Answered from the headers, before the body is uploaded at all."""
    response = await storage.post(
        "/storage/bookmarks",
        json_body=[],
        headers={"X-Weave-Records": str(LIMITS.max_post_records + 1)},
    )
    assert response.status_code == 413
    assert response.json() == 17


# --------------------------------------------------------------------------
# Reading, in detail.
# --------------------------------------------------------------------------


async def test_newlines_format_is_one_record_per_line(
    storage: SyncStorageClient,
) -> None:
    await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": "a", "payload": "1"}, {"id": "b", "payload": "2"}],
    )
    response = await storage.get(
        "/storage/bookmarks",
        params={"full": ""},
        headers={"accept": "application/newlines"},
    )
    assert response.headers["content-type"].startswith("application/newlines")
    records = [json.loads(line) for line in response.text.splitlines()]
    assert sorted(item["id"] for item in records) == ["a", "b"]


async def test_a_limited_read_offers_the_offset_that_continues_it(
    storage: SyncStorageClient,
) -> None:
    await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": f"id{i}", "payload": str(i)} for i in range(5)],
    )
    first = await storage.get(
        "/storage/bookmarks", params={"full": "", "limit": "2", "sort": "newest"}
    )
    assert len(first.json()) == 2
    offset = first.headers["X-Weave-Next-Offset"]

    second = await storage.get(
        "/storage/bookmarks",
        params={"full": "", "limit": "2", "sort": "newest", "offset": offset},
    )
    first_ids = {item["id"] for item in first.json()}
    second_ids = {item["id"] for item in second.json()}
    assert not (first_ids & second_ids)


async def test_ids_selects_records(storage: SyncStorageClient) -> None:
    await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": f"id{i}", "payload": str(i)} for i in range(4)],
    )
    response = await storage.get("/storage/bookmarks", params={"ids": "id1,id3"})
    assert sorted(response.json()) == ["id1", "id3"]


async def test_deleting_by_ids_leaves_the_rest(storage: SyncStorageClient) -> None:
    await storage.post(
        "/storage/bookmarks",
        json_body=[{"id": f"id{i}", "payload": str(i)} for i in range(4)],
    )
    response = await storage.delete("/storage/bookmarks", params={"ids": "id1,id3"})
    assert response.status_code == 200
    assert sorted((await storage.get("/storage/bookmarks")).json()) == ["id0", "id2"]


async def test_an_unknown_sort_is_refused(storage: SyncStorageClient) -> None:
    """A client that asked for an order would page through believing it got one."""
    response = await storage.get("/storage/bookmarks", params={"sort": "sideways"})
    assert response.status_code == 400


async def test_collection_counts_and_usage_report_what_is_stored(
    storage: SyncStorageClient,
) -> None:
    await storage.post(
        "/storage/bookmarks", json_body=[{"id": "a", "payload": "x" * 1024}]
    )
    counts = await storage.get("/info/collection_counts")
    assert counts.json() == {"bookmarks": 1}
    usage = await storage.get("/info/collection_usage")
    assert usage.json() == {"bookmarks": 1.0}
    quota = await storage.get("/info/quota")
    assert quota.json() == [1.0, None]


async def test_a_ttl_expires_a_record(storage: SyncStorageClient) -> None:
    await _put(storage, "bookmarks", "brief", payload="x", ttl=0)
    assert (await storage.get("/storage/bookmarks")).json() == []


async def test_an_unknown_endpoint_under_storage_answers_in_sync_dialect(
    storage: SyncStorageClient, http
) -> None:
    response = await http.get(f"{storage.prefix}/info/nothing")
    assert response.status_code == 404
    assert response.json() == 0


async def test_a_second_write_inside_the_same_hundredth_conflicts(
    storage: SyncStorageClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rule the retry above exists for.

    Two writes to one collection cannot share a timestamp, or a client that has
    already polled `?newer=` that instant would never see the second. Upstream
    answers with a 503 and a `Retry-After` rather than letting the write land
    where nobody will look for it.

    The clock is frozen rather than raced: an in-process PUT takes a couple of
    milliseconds, so two of them land in the same hundredth most of the time
    but not all of it, and a test that asserts a conflict has to *cause* one.
    """

    class Frozen:
        """`time.time` as the storage app sees it, stopped mid-hundredth."""

        instant = time.time()

        @staticmethod
        def time() -> float:
            return Frozen.instant

    monkeypatch.setattr(syncstorage, "time", Frozen)

    await _put(storage, "bookmarks", "abc", payload="first")
    response = await storage.put(
        "/storage/bookmarks/abc",
        json_body={"payload": "second"},
        retry_on_conflict=False,
    )
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "10"
