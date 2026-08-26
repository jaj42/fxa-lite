# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Sync 1.5's error envelope — the third and last shape fxa-lite speaks.

`syncserver/src/error.rs`.  The accounts API answers with
`{code, errno, error, message, info}`, the tokenserver with
`{status, errors:[...]}`, and Sync storage with **a bare JSON integer**: the
Weave error code, alone, as the whole body.

    HTTP/1.1 400 Bad Request
    Content-Type: application/json

    8

That is not an oversight to be tidied up.  Sync 1.5 inherited the wire format
from Sync 1.1 and `ResponseError::error_response` says so in a comment: a
descriptive body is right there, commented out, kept that way for backwards
compatibility.  Firefox reads the integer.

The code matters less than the status — `8` (invalid WBO) tells the client its
record was malformed and will never be accepted, where `0` says only "no",
and a 503 with `Retry-After` says "ask again shortly".  The status is what
decides whether the client drops the record, retries, or gives up on the
collection.
"""

from __future__ import annotations

from enum import IntEnum


class WeaveError(IntEnum):
    """`error.rs`'s `WeaveError`. Only these six values are ever sent."""

    UNKNOWN = 0
    ILLEGAL_METHOD = 1
    MALFORMED_JSON = 6
    INVALID_WBO = 8
    OVER_QUOTA = 14
    SIZE_LIMIT_EXCEEDED = 17


#: What a conflicting write is told to wait, in seconds. `error.rs`'s `RETRY_AFTER`.
RETRY_AFTER = 10


class SyncStorageError(Exception):
    """An error with Sync 1.5's wire representation."""

    def __init__(
        self,
        status_code: int,
        weave: WeaveError = WeaveError.UNKNOWN,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(f"{status_code} weave:{int(weave)}")
        self.status_code = status_code
        self.weave = weave
        self.headers = headers or {}

    @property
    def payload(self) -> int:
        """The entire response body: one integer."""
        return int(self.weave)


def unauthorized() -> SyncStorageError:
    """Every HAWK failure, without distinction.

    Upstream separates a missing header from a bad MAC from an expired token
    for its metrics, but every one of them leaves the wire as the same 401 with
    the same body — and rightly so: the client's only move is to fetch a fresh
    token from the tokenserver.
    """
    return SyncStorageError(401)


def invalid_wbo() -> SyncStorageError:
    """A body that is not a usable Basic Storage Object."""
    return SyncStorageError(400, WeaveError.INVALID_WBO)


def bad_request() -> SyncStorageError:
    return SyncStorageError(400)


def not_found() -> SyncStorageError:
    """A collection or BSO id that cannot exist, or an endpoint we do not serve."""
    return SyncStorageError(404)


def not_acceptable() -> SyncStorageError:
    """`Accept` names no content type we can produce."""
    return SyncStorageError(406)


def unsupported_media_type() -> SyncStorageError:
    return SyncStorageError(415)


def request_too_large(weave: WeaveError = WeaveError.SIZE_LIMIT_EXCEEDED) -> SyncStorageError:
    return SyncStorageError(413, weave)


def over_quota() -> SyncStorageError:
    return SyncStorageError(403, WeaveError.OVER_QUOTA)


def conflict() -> SyncStorageError:
    """A write that would not move the collection's timestamp forward.

    503, not the 409 the protocol specification asks for: upstream's comment
    cites two client bugs (bugzilla 959034, 959032) for the choice, and a
    client that mishandles a 409 is a client that corrupts its own state.
    `Retry-After` is what turns this into a pause rather than a failure.
    """
    return SyncStorageError(
        503, WeaveError.UNKNOWN, headers={"Retry-After": str(RETRY_AFTER)}
    )


def internal_error() -> SyncStorageError:
    return SyncStorageError(500)


__all__ = [
    "RETRY_AFTER",
    "SyncStorageError",
    "WeaveError",
    "bad_request",
    "conflict",
    "internal_error",
    "invalid_wbo",
    "not_acceptable",
    "not_found",
    "over_quota",
    "request_too_large",
    "unauthorized",
    "unsupported_media_type",
]
