"""Request tracing: what phase 8 needed a throwaway proxy to see.

An access log line says a request was a 400.  It does not say which field was
wrong, and for this protocol that is the only interesting part — the difference
between "Firefox sent a grant type we refuse" and "Firefox sent a field our
schema forbids" is two lines of JSON that never reach the terminal.  Phase 8
was debugged by wrapping the app in a one-off ASGI tap that printed them.  This
is that tap, made permanent and made safe.

Two things make it safe enough to ship enabled-by-config rather than
commented-out-in-a-branch:

* **Bodies appear only at `DEBUG`.**  At the default level this middleware
  renders nothing and costs one `isEnabledFor` call per request.
* **Every value that could be replayed is redacted before it is written.**  A
  password verifier, a session token, a key bundle and an access token are all
  reduced to a recognisable prefix and a length.  A prefix is enough to match
  one log line against another — which is the whole reason to want the value —
  and not enough to use.

Redaction is by key name, so it is exactly as good as `SECRET_KEYS`.  The rule
for adding to that list: **if holding the value would let someone act as the
user, it goes in.**  When in doubt it goes in; a redacted field that did not
need to be costs a debugging session nothing, and the reverse writes a Sync
key to a file.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import parse_qsl, urlencode

#: Everything below `fxa_lite` inherits this, so one level controls the lot.
LOGGER_NAME = "fxa_lite"
logger = logging.getLogger(LOGGER_NAME)

#: JSON keys and query parameters whose values are credentials. Names are the
#: wire's, so both spellings of a thing appear where the protocol uses both.
SECRET_KEYS = frozenset(
    {
        "access_token",
        "assertion",
        "authPW",
        "authorization",
        "bundle",
        "client_secret",
        "code",
        "code_verifier",
        "id_token",
        # The tokenserver's own answer: the derived HAWK MAC key. Nothing else
        # fxa-lite emits uses this name, so it is safe to redact globally —
        # unlike its companion `id`, which is below.
        "key",
        "keyFetchToken",
        "keyRotationSecret",
        "keys_jwe",
        "oldAuthPW",
        "passwordChangeToken",
        "payload",
        # A push subscription's keys. Not ours to spend, but they are somebody
        # else's credential and a log is not where they belong.
        "pushAuthKey",
        "pushPublicKey",
        "refresh_token",
        "sessionToken",
        "subject_token",
        "token",
        "unwrapBKey",
        "wrapKb",
    }
)

#: Names that are a credential *on some paths and not on others*, so they
#: cannot go in `SECRET_KEYS` without redacting something harmless everywhere.
#:
#: There is one: `id`. `/token/1.0/sync/1.5` answers `{"id": ..., "key": ...}`
#: where `id` is the HAWK credential the client then presents to `/storage` —
#: half of a complete, spendable Sync credential. Everywhere else `id` is a BSO
#: id, a device id or a client id, all of which a debugging session needs to
#: read.
PATH_SECRET_KEYS: tuple[tuple[str, frozenset[str]], ...] = (("/token/", frozenset({"id"})),)

#: Long enough to tell two tokens apart in a log, far too short to present one.
PREFIX_LENGTH = 8
#: A value shorter than this cannot be a credential, and truncating it would
#: only hide something like `"type": "desktop"`.
MIN_REDACTED_LENGTH = 16
#: Sync uploads run to megabytes of ciphertext. The first couple of kilobytes
#: say what shape the request was, which is what tracing is for.
MAX_BODY_CHARS = 2048

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def configure(level: str) -> None:
    """Attach a handler to the `fxa_lite` logger and set its level.

    Uvicorn owns the root logger and its own access log; this deliberately does
    not touch either. `propagate = False` keeps our lines from being formatted
    a second time by whatever uvicorn has installed above us.
    """
    logger.setLevel(level.upper())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
        logger.addHandler(handler)
    logger.propagate = False


def secrets_for(path: str) -> frozenset[str]:
    """`SECRET_KEYS`, plus anything this path makes a credential."""
    extra = frozenset().union(
        *(names for prefix, names in PATH_SECRET_KEYS if path.startswith(prefix))
    )
    return SECRET_KEYS | extra if extra else SECRET_KEYS


def redact(node: Any, secrets: frozenset[str] = SECRET_KEYS) -> Any:
    """Walk a decoded JSON document, replacing credentials with a prefix."""
    if isinstance(node, dict):
        return {key: _value(key, item, secrets) for key, item in node.items()}
    if isinstance(node, list):
        return [redact(item, secrets) for item in node]
    return node


def _value(key: str, node: Any, secrets: frozenset[str]) -> Any:
    if key in secrets:
        return _elide(node, secrets)
    return redact(node, secrets)


def _elide(node: Any, secrets: frozenset[str] = SECRET_KEYS) -> Any:
    """Keep the shape, lose the secret."""
    if isinstance(node, str) and len(node) > MIN_REDACTED_LENGTH:
        return f"{node[:PREFIX_LENGTH]}…({len(node)} chars)"
    if isinstance(node, str):
        return "…"
    # A non-string under a secret name is a nested envelope, not a credential
    # in itself; its own leaves are still subject to the same rules.
    return redact(node, secrets)


def render_body(raw: bytes, secrets: frozenset[str] = SECRET_KEYS) -> str:
    """A redacted, truncated, single-line rendering of a request or response."""
    if not raw:
        return "(empty)"
    try:
        decoded = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        # `application/newlines`, form bodies, static assets: the size is the
        # only thing that can be said without guessing at the encoding.
        return f"<{len(raw)} bytes, not JSON>"
    rendered = json.dumps(redact(decoded, secrets), sort_keys=True, ensure_ascii=False)
    if len(rendered) > MAX_BODY_CHARS:
        return f"{rendered[:MAX_BODY_CHARS]}… ({len(rendered)} chars)"
    return rendered


def render_query(raw: bytes, secrets: frozenset[str] = SECRET_KEYS) -> str:
    """Query strings carry credentials too — `?code=` on an OAuth redirect."""
    if not raw:
        return ""
    pairs = parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return urlencode(
        [(key, _elide(value) if key in secrets else value) for key, value in pairs]
    )


def render_authorization(header: str | None) -> str:
    """The scheme, and enough of the credential to correlate two requests.

    The scheme alone answers most auth questions — a Sync request arriving with
    `Bearer` instead of `Hawk` is the bug — and the token itself is precisely
    what must not be written down.
    """
    if not header:
        return "none"
    scheme, _, rest = header.partition(" ")
    if not rest:
        return scheme
    return f"{scheme} {rest[:PREFIX_LENGTH]}…"


class Trace:
    """Pure ASGI so the request stream is passed through, not buffered.

    Starlette's `BaseHTTPMiddleware` would have to consume the body to read it
    and then replay it downstream; wrapping `receive` and `send` instead means
    the application sees exactly the messages it would have seen, and a body
    that is never read here is never read at all.
    """

    #: Assets are served by the hundred and say nothing about the protocol.
    SKIP_PREFIXES = ("/static/",)

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or not logger.isEnabledFor(logging.DEBUG)
            or path.startswith(self.SKIP_PREFIXES)
        ):
            await self.app(scope, receive, send)
            return

        request_body = bytearray()
        response_body = bytearray()
        status = 0

        async def traced_receive() -> MutableMapping[str, Any]:
            message = await receive()
            if message["type"] == "http.request":
                request_body.extend(message.get("body", b""))
            return message

        async def traced_send(message: MutableMapping[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, traced_receive, traced_send)
        finally:
            # In a `finally` so a request that raises is still described. An
            # unhandled exception is the case where the body matters most.
            self._log(scope, path, status, bytes(request_body), bytes(response_body))

    def _log(
        self, scope: Scope, path: str, status: int, request_body: bytes, response_body: bytes
    ) -> None:
        secrets = secrets_for(path)
        query = render_query(scope.get("query_string", b""), secrets)
        target = f"{path}?{query}" if query else path
        logger.debug(
            "%s %s -> %s auth=%s\n    request : %s\n    response: %s",
            scope.get("method", "?"),
            target,
            status or "(no response)",
            render_authorization(_header(scope, b"authorization")),
            render_body(request_body, secrets),
            render_body(response_body, secrets),
        )


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None
