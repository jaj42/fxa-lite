# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Reading a Sync 1.5 request: query string, headers, and BSO bodies.

`syncserver/src/web/extractors/`.  This is the layer with the most protocol in
it and the least obvious rules, because Sync 1.5 predates every convention a
modern API would follow:

* a **query parameter present with no value** means true (`?full`), so `full`
  is "was the key there at all", not "did it say true";
* `ids` is one comma-separated parameter, capped at 100;
* a **malformed record in a POST is not an error** — it comes back in the
  response's `failed` map while its neighbours are stored, because a client
  that has one bad record must still be able to sync the other four hundred;
* a malformed record in a *PUT*, where there is only one, is a 400;
* and the whole body may arrive as `application/newlines`, one JSON object per
  line, which is how a large upload avoids being one enormous array.

Validation lives here rather than in pydantic models because the rules are
per-record and recoverable: pydantic would reject the request, and rejecting
the request is the wrong answer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import errors
from .store import SORT_NONE, SORTINGS, BsoQuery, Offset, quantize

# DIVERGENCE: bso-id-with-a-slash-unroutable — a record id containing `/` has no URL
#   upstream: `extractors/bso_param.rs` splits the *raw* path on `/`, requires
#     six elements, and percent-decodes the sixth. `%2F` inside an id is
#     therefore an ordinary character, and `/1.5/1/storage/bookmarks/a%2Fb`
#     addresses the record whose id is `a/b`.
#   fxa-lite: the router matches `scope["path"]`, which the server decoded
#     before we saw it, so that same target is seven segments and 404s. Every
#     other escape works: the MAC covers the raw target (`_signed_target`) and
#     the id is validated after decoding, exactly as upstream validates it.
#   why: the routing is Starlette's, and the alternative is to dispatch the
#     storage tier off the raw path ourselves — a second router beside the
#     framework's — to reach ids no Sync client mints. Sync ids are GUIDs and
#     base64url; the `/` case is reachable only by hand.
#   cost: nothing can be stored that cannot be read back. Such a record is
#     created through POST, where the id is in the body rather than the URL,
#     and listed, fetched and deleted through `?ids=`, where it is in the query
#     string. Only the per-record URL cannot name it.

#: `BSO_ID_REGEX` — any printable ASCII, up to 64 characters.
BSO_ID_RE = re.compile(r"^[ -~]{1,64}$")
#: `COLLECTION_ID_REGEX`.
COLLECTION_RE = re.compile(r"^[a-zA-Z0-9._-]{1,32}$")

#: `BATCH_MAX_IDS` — the cap on `?ids=`.
MAX_IDS = 100

#: `BSO_MAX_TTL` and the sortindex bounds, from `extractors/constants.rs`.
MAX_TTL = 999_999_999
MAX_SORTINDEX = 999_999_999
MIN_SORTINDEX = -999_999_999

#: `ACCEPTED_CONTENT_TYPES`. `text/plain` is there for clients old enough to
#: have avoided a CORS preflight by lying about the body.
CONTENT_TYPES = ("application/json", "text/plain", "application/newlines")

#: The one payload known to be produced by a broken client: an all-zero IV
#: means the record is encrypted with a key the client did not actually have.
#: Storing it would poison the collection for every other device.
KNOWN_BAD_PAYLOAD_RE = re.compile(r'IV":\s*"AAAAAAAAAAAAAAAAAAAAAA==')

#: `?commit=` — case-insensitively the word "true", and nothing else.
TRUE_RE = re.compile(r"^true$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Limits:
    """`ServerLimits`, as `/info/configuration` reports them.

    Fixed rather than configurable: they are what every Firefox has been
    written against, and a household server has no reason to be the one place
    in the ecosystem where a client discovers a limit it has never seen.
    """

    max_post_bytes: int = 2_621_440
    max_post_records: int = 100
    max_record_payload_bytes: int = 2_621_440
    max_request_bytes: int = 2_621_440 + 4096
    max_total_bytes: int = 100 * 2_621_440
    max_total_records: int = 10_000
    max_quota_limit: int = 2_097_152_000

    def as_json(self) -> dict[str, int]:
        return {
            "max_post_bytes": self.max_post_bytes,
            "max_post_records": self.max_post_records,
            "max_record_payload_bytes": self.max_record_payload_bytes,
            "max_request_bytes": self.max_request_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_total_records": self.max_total_records,
            "max_quota_limit": self.max_quota_limit,
        }


LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class PostedBso:
    """One record from a POST or PUT body, already known to be well formed."""

    id: str
    payload: str | None = None
    sortindex: int | None = None
    ttl: int | None = None

    @property
    def payload_size(self) -> int:
        return len(self.payload or "")


@dataclass(slots=True)
class PostedBsos:
    """A parsed POST body: what will be stored, and what will not."""

    valid: list[PostedBso] = field(default_factory=list)
    #: id -> why. Returned to the client as `failed`; these are not errors.
    invalid: dict[str, str] = field(default_factory=dict)


def validate_collection(name: str) -> str:
    """A name that cannot exist is a 404, not a 400 — there is nothing there."""
    if not COLLECTION_RE.match(name):
        raise errors.not_found()
    return name


def validate_bso_id(bso_id: str) -> str:
    if not BSO_ID_RE.match(bso_id):
        raise errors.not_found()
    return bso_id


def parse_query(params: Any) -> BsoQuery:
    """The `?newer=&older=&sort=&limit=&offset=&ids=&full` set.

    The offset/bound cross-check at the end is upstream's: a token whose
    timestamp falls outside the `newer`/`older` window cannot have come from a
    page of this query, so it is either stale or forged, and continuing from it
    would silently return the wrong records.
    """
    newer = _timestamp(params, "newer")
    older = _timestamp(params, "older")
    sort = params.get("sort")
    if sort == SORT_NONE:
        # `sort=none` is upstream's default variant, and it asks for no order.
        # Normalising it to the absent case here rather than carrying the
        # string is what keeps every comparison below — and `get_bsos`'s offset
        # resumption — reading the way upstream's `Sorting::Newest | None` and
        # `_` arms read, without a second spelling to remember.
        sort = None
    elif sort is not None and sort not in SORTINGS:
        # An unrecognised sort is not "no sort": the client asked for an order
        # and would page through the answer believing it got one.
        raise errors.bad_request()

    limit = None
    if (raw := params.get("limit")) is not None:
        try:
            limit = int(raw)
        except ValueError as exc:
            raise errors.bad_request() from exc
        if limit < 0:
            raise errors.bad_request()

    offset = None
    if (raw := params.get("offset")) is not None:
        try:
            offset = Offset.parse(raw)
        except ValueError as exc:
            raise errors.bad_request() from exc

    ids = tuple(part.strip() for part in params.get("ids", "").split(",") if part.strip())
    if len(ids) > MAX_IDS:
        raise errors.bad_request()
    if any(not BSO_ID_RE.match(value) for value in ids):
        raise errors.bad_request()

    query = BsoQuery(newer=newer, older=older, sort=sort, limit=limit, offset=offset, ids=ids)
    if sort != "index" and offset is not None and offset.timestamp is not None:
        bound = offset.timestamp
        if newer is not None and bound < newer:
            raise errors.bad_request()
        if newer is None and older is not None and bound > older:
            raise errors.bad_request()
    return query


def _timestamp(params: Any, name: str) -> int | None:
    """`SyncTimestamp::from_header`: seconds as a float, into whole hundredths."""
    raw = params.get(name)
    if raw is None:
        return None
    return parse_timestamp(raw)


def parse_timestamp(raw: str) -> int:
    try:
        seconds = float(raw)
    except ValueError as exc:
        raise errors.bad_request() from exc
    if seconds < 0 or seconds != seconds or seconds > (2**64 - 1) / 1000:
        raise errors.bad_request()
    return quantize(int(seconds * 1000))


def wants_newlines(accept: str | None) -> bool:
    """`get_accepted`: the first acceptable type, by quality then by order.

    `*/*` means "whatever you were going to send", so it resolves to JSON
    rather than to the first thing in our own list.
    """
    if not accept:
        return False
    candidates: list[tuple[float, int, str]] = []
    for index, part in enumerate(accept.split(",")):
        media, _, parameters = part.strip().partition(";")
        media = media.strip().lower()
        if not media:
            continue
        quality = 1.0
        for parameter in parameters.split(";"):
            key, _, value = parameter.partition("=")
            if key.strip() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 1.0
        candidates.append((-quality, index, media))
    for _, _, media in sorted(candidates):
        if media == "*/*":
            return False
        if media in CONTENT_TYPES:
            return media == "application/newlines"
    if candidates:
        raise errors.not_acceptable()
    return False


def check_content_type(content_type: str | None) -> str:
    """Sync speaks three content types and refuses everything else with a 415."""
    media = (content_type or "application/json").partition(";")[0].strip().lower()
    if media not in CONTENT_TYPES:
        raise errors.unsupported_media_type()
    return media


def parse_bso_body(body: bytes, content_type: str | None) -> PostedBso:
    """The body of a `PUT /storage/{collection}/{bso}` — exactly one record.

    The id here is the one in the path, so the body's own `id` is validated but
    the caller supplies the real one. Unknown fields are rejected outright
    rather than dropped: `modified` and `collection` are the two a client is
    allowed to send and have ignored, and anything else is a client sending
    something it believes will be stored.
    """
    check_content_type(content_type)
    try:
        value = json.loads(body or b"{}")
    except ValueError as exc:
        raise errors.invalid_wbo() from exc
    if not isinstance(value, dict):
        raise errors.invalid_wbo()
    try:
        bso = _bso_from_object(value, require_id=False)
    except ValueError as exc:
        raise errors.invalid_wbo() from exc
    if bso.payload_size > LIMITS.max_record_payload_bytes:
        raise errors.request_too_large()
    return bso


def parse_bso_bodies(body: bytes, content_type: str | None) -> PostedBsos:
    """The body of a `POST /storage/{collection}` — a list, or one per line.

    Records that fail validation land in `invalid` rather than failing the
    request, but three things still fail the whole thing: a body that is not
    JSON at all, a record that is not an object, and a missing or duplicated
    id. Those are not "one bad record" — they mean the server cannot tell which
    records the client meant, so reporting per-record results would be a
    guess.
    """
    media = check_content_type(content_type)
    text = body.decode("utf-8", errors="replace")
    raw: list[Any] = []
    if media == "application/newlines":
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                raw.append(json.loads(line))
            except ValueError as exc:
                raise errors.invalid_wbo() from exc
    else:
        try:
            raw = json.loads(text or "[]")
        except ValueError as exc:
            raise errors.invalid_wbo() from exc
        if not isinstance(raw, list):
            raise errors.invalid_wbo()

    result = PostedBsos()
    seen: set[str] = set()
    total_payload = 0
    for item in raw:
        if not isinstance(item, dict):
            raise errors.invalid_wbo()
        bso_id = item.get("id")
        if not isinstance(bso_id, str):
            raise errors.invalid_wbo()
        if bso_id in seen:
            raise errors.invalid_wbo()
        seen.add(bso_id)
        try:
            bso = _bso_from_object(item, require_id=True)
        except ValueError as exc:
            result.invalid[bso_id] = str(exc)
            continue
        total_payload += bso.payload_size
        if (
            bso.payload_size > LIMITS.max_record_payload_bytes
            or total_payload > LIMITS.max_post_bytes
        ):
            # "retry bytes" is upstream's wording and it is an instruction: the
            # record is fine, the request was too full, send it again alone.
            result.invalid[bso.id] = "retry bytes"
            continue
        result.valid.append(bso)

    # Anything past the per-request record cap is likewise deferred, not lost.
    while len(result.valid) > LIMITS.max_post_records:
        dropped = result.valid.pop()
        result.invalid[dropped.id] = "retry bso"
    return result


def check_known_bad_payload(bsos: list[PostedBso], collection: str) -> None:
    """`crypto` is where the collection keys live; a bad record there is fatal.

    Everywhere else a broken payload costs one record. In `crypto` it costs the
    collection: every other device would decrypt against a key bundle it cannot
    read and conclude its own data is corrupt.
    """
    if collection != "crypto":
        return
    for bso in bsos:
        if bso.payload and KNOWN_BAD_PAYLOAD_RE.search(bso.payload):
            raise errors.invalid_wbo()


def _bso_from_object(value: dict[str, Any], *, require_id: bool) -> PostedBso:
    """Raises `ValueError` with the reason, which becomes the `failed` entry."""
    unknown = set(value) - {"id", "sortindex", "payload", "ttl", "modified", "collection"}
    if unknown:
        raise ValueError(f"unknown field {sorted(unknown)[0]}")

    bso_id = value.get("id")
    if (require_id or bso_id is not None) and (
        not isinstance(bso_id, str) or not BSO_ID_RE.match(bso_id)
    ):
        raise ValueError("invalid bso: id")

    payload = value.get("payload")
    if payload is not None and not isinstance(payload, str):
        raise ValueError("invalid bso: payload")

    sortindex = value.get("sortindex")
    if sortindex is not None:
        if not isinstance(sortindex, int) or isinstance(sortindex, bool):
            raise ValueError("invalid bso: sortindex")
        if not MIN_SORTINDEX <= sortindex <= MAX_SORTINDEX:
            raise ValueError("invalid bso: sortindex")

    ttl = value.get("ttl")
    if ttl is not None and (
        not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0 or ttl > MAX_TTL
    ):
        raise ValueError("invalid bso: ttl")

    return PostedBso(
        id=bso_id if isinstance(bso_id, str) else "",
        payload=payload,
        sortindex=sortindex,
        ttl=ttl,
    )


@dataclass(frozen=True, slots=True)
class BatchRequest:
    """`?batch=` / `?commit=`, once they have been made sense of."""

    #: `None` means "open a new batch"; a string is an existing one.
    id: str | None
    commit: bool


def parse_batch(params: Any) -> BatchRequest | None:
    """`?batch` absent entirely means this POST is not batched at all.

    `?batch` with no value, or the literal `true`, opens a new batch — the same
    spelling `?full` uses, and the reason `commit` without `batch` is an error
    rather than being read as "commit whatever".
    """
    batch = params.get("batch")
    commit = params.get("commit")
    if batch is None and commit is None:
        return None
    if batch is None:
        raise errors.bad_request()
    if commit is not None and not TRUE_RE.match(commit):
        raise errors.bad_request()
    identifier = None if batch == "" or TRUE_RE.match(batch) else batch
    return BatchRequest(id=identifier, commit=commit is not None)


def check_batch_headers(headers: Any) -> None:
    """`X-Weave-Records` and friends: what the client says it is about to send.

    Answering before the body arrives is the point — a client that announces a
    hundred megabytes should be told no while it can still split the upload,
    not after it has uploaded.
    """
    checks = (
        ("x-weave-records", LIMITS.max_post_records),
        ("x-weave-bytes", LIMITS.max_post_bytes),
        ("x-weave-total-records", LIMITS.max_total_records),
        ("x-weave-total-bytes", LIMITS.max_total_bytes),
    )
    for header, limit in checks:
        raw = headers.get(header)
        if raw is None:
            continue
        try:
            declared = int(raw)
        except ValueError as exc:
            raise errors.bad_request() from exc
        if declared > limit:
            raise errors.request_too_large()


def check_content_length(headers: Any) -> None:
    if (raw := headers.get("content-length")) is None:
        return
    try:
        length = int(raw)
    except ValueError:
        return
    if length > LIMITS.max_request_bytes:
        raise errors.request_too_large()


__all__ = [
    "BSO_ID_RE",
    "COLLECTION_RE",
    "CONTENT_TYPES",
    "LIMITS",
    "MAX_IDS",
    "BatchRequest",
    "Limits",
    "PostedBso",
    "PostedBsos",
    "check_batch_headers",
    "check_content_length",
    "check_content_type",
    "check_known_bad_payload",
    "parse_batch",
    "parse_bso_bodies",
    "parse_bso_body",
    "parse_query",
    "parse_timestamp",
    "validate_bso_id",
    "validate_collection",
    "wants_newlines",
]
