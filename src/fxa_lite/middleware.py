"""Two pure-ASGI middlewares that have to run outside the routes.

Both exist because a FastAPI dependency is too late.  A route function is
called after Starlette has parsed the request and after the body has been
buffered, which is precisely the wrong side of the two problems here:

* `BodyLimit` refuses an oversized body *before* anything reads it.  Every
  authenticated tier has to read the body before it can check the signature —
  the signature may cover the body — so "authenticate first" is not available
  as an answer, and `uvicorn` imposes no limit of its own.
* `SecurityHeaders` stamps responses the routes never see: a 404 rendered by an
  exception handler, a 413 from `BodyLimit` above, an asset served straight
  from memory.

Written as raw ASGI rather than `BaseHTTPMiddleware` for the reason `tracing`
gives: `BaseHTTPMiddleware` reads the request body to hand it on, which is the
exact behaviour `BodyLimit` exists to prevent.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from . import errors
from .syncstorage import errors as sync_errors
from .syncstorage.models import LIMITS
from .syncstorage.store import quantize, timestamp_header
from .tokenserver import errors as tokenserver_errors

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

#: What every tier but Sync storage may send. The largest legitimate body
#: outside `/storage` is an OAuth request carrying a `keys_jwe`, which is a few
#: hundred bytes; 64 KiB is room for a client that surprises us and nothing
#: like enough to be an allocation an attacker chooses.
DEFAULT_MAX_BODY_BYTES = 64 * 1024

#: `X-Content-Type-Options`, and a policy for responses that are not documents.
#: `default-src 'none'` says this JSON is not a page: nothing it might be
#: coaxed into being rendered as may load anything or run anything.
NOSNIFF = "nosniff"
API_CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'"


class BodyLimit:
    """Refuse a request body larger than its tier allows, before it is read.

    Two paths, because the cheap one covers every real client:

    * A declared `Content-Length` over the limit is refused without reading a
      byte. `h11` — and therefore `uvicorn` — will not deliver more body than
      the declared length, so a client that declares an acceptable size cannot
      then exceed it, and nothing further needs counting.
    * A chunked body declares nothing, so it is counted as it arrives and the
      request is refused the moment it passes the limit. Only what fits is ever
      held, and the application is not started at all.

    The refusal is rendered here, by hand, in the envelope the path's tier
    speaks: this runs outside the exception handlers in `app.py`, and a Sync
    client handed the accounts envelope reads a JSON object where the protocol
    says an integer.
    """

    def __init__(
        self,
        app: Any,
        *,
        storage_prefix: str,
        tokenserver_prefix: str,
        default_limit: int = DEFAULT_MAX_BODY_BYTES,
        storage_limit: int = LIMITS.max_request_bytes,
    ) -> None:
        self.app = app
        self.storage_prefix = storage_prefix
        self.tokenserver_prefix = tokenserver_prefix
        self.default_limit = default_limit
        #: `/info/configuration` advertises `max_request_bytes` and Firefox
        #: believes it, so the cap below `/storage` has to be exactly that
        #: number — a stricter one turns a legal batch into a stalled sync.
        self.storage_limit = storage_limit

    def limit_for(self, path: str) -> int:
        if path.startswith(f"{self.storage_prefix}/"):
            return self.storage_limit
        return self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        limit = self.limit_for(path)
        declared = _content_length(scope)
        if declared is not None:
            if declared > limit:
                await self._refuse(path, send)
                return
            # Declared and acceptable: the server will not deliver more than it
            # says, so there is nothing to count and nothing to buffer.
            await self.app(scope, receive, send)
            return
        if not _has_body(scope):
            # A GET, or anything else with neither a length nor a chunked
            # encoding: there is no body to read, and pretending to read one
            # would block until the client sent something.
            await self.app(scope, receive, send)
            return

        body, oversized = await self._buffer(receive, limit)
        if oversized:
            await self._refuse(path, send)
            return
        await self.app(scope, _replay(body), send)

    async def _buffer(self, receive: Receive, limit: int) -> tuple[bytes, bool]:
        """Read a chunked body up to `limit`, and say whether it went past it."""
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                # `http.disconnect`: the client gave up mid-body. Hand the
                # application what arrived and let it answer as it would.
                return b"".join(chunks), False
            chunk = bytes(message.get("body", b""))
            total += len(chunk)
            if total > limit:
                # Nothing is kept: the point of refusing here is that the
                # oversized body never becomes an allocation.
                return b"", True
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks), False

    async def _refuse(self, path: str, send: Send) -> None:
        status, headers, body = self._envelope(path)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    *headers,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _envelope(self, path: str) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        if path.startswith(f"{self.storage_prefix}/"):
            error = sync_errors.request_too_large()
            now = quantize(int(time.time() * 1000))
            return (
                error.status_code,
                [(b"x-weave-timestamp", timestamp_header(now).encode())],
                _json(error.payload),
            )
        if path.startswith(f"{self.tokenserver_prefix}/"):
            # The tokenserver takes no body at all, so this is only reachable
            # by a client sending one anyway — but its parser is still the one
            # that has to read the answer.
            failure = tokenserver_errors.TokenserverError(
                location="body", description="Request body too large", http_status=413
            )
            return failure.http_status, [], _json(failure.payload)
        accounts_error = errors.request_body_too_large()
        return accounts_error.code, [], _json(accounts_error.payload)


class SecurityHeaders:
    """`nosniff` and a null CSP on every response that has not set its own.

    The content server sets a full policy on its documents and its assets
    (`content/__init__.py`); everything else fxa-lite serves is JSON, which
    wants exactly two headers and never wanted them enough for anybody to write
    them out per route. Setting them here means a 404 from an exception handler
    and a 413 from `BodyLimit` get them too.

    Nothing already present is overwritten: a route that has thought about its
    own policy has thought about it harder than this has.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def stamped(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {key.lower() for key, _ in headers}
                if b"x-content-type-options" not in present:
                    headers.append((b"x-content-type-options", NOSNIFF.encode()))
                if b"content-security-policy" not in present:
                    headers.append(
                        (b"content-security-policy", API_CONTENT_SECURITY_POLICY.encode())
                    )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, stamped)


def _json(payload: Any) -> bytes:
    return json.dumps(payload).encode()


def _content_length(scope: Scope) -> int | None:
    raw = _header(scope, b"content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        # Malformed: treat it as undeclared and count the body instead. `h11`
        # will refuse the request on its own account before we see much of it.
        return None


def _has_body(scope: Scope) -> bool:
    return _header(scope, b"transfer-encoding") is not None


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _replay(body: bytes) -> Receive:
    """A `receive` that hands the application the body already read.

    Anything asked for after it gets `http.disconnect`, which is what an ASGI
    server sends once a request body is exhausted and the connection is done.
    """
    sent = False

    async def receive() -> MutableMapping[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


__all__ = [
    "API_CONTENT_SECURITY_POLICY",
    "DEFAULT_MAX_BODY_BYTES",
    "BodyLimit",
    "SecurityHeaders",
]
