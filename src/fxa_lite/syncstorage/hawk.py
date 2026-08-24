"""HAWK, verified for real this time.

The accounts API accepts a `Hawk` header and throws the MAC away — that is
what the reference auth server does (`hawk-fxa-token.js`), and `auth/
credentials.py` says so at length.  Sync storage is a different protocol that
happens to share the word: here the MAC *is* the authorization.  There is no
session to look up, no row to check; the token carries its own claims and the
key that signs the request is derived from those claims plus a secret only the
two tiers know.  Skip the MAC and anyone holding a token id — which travels in
the clear in every request — can spend it.

The normalized string being MAC'd is the one from the HAWK specification, and
`syncserver/src/web/auth.rs` builds it with the `hawk` crate:

    hawk.1.header\\n
    <ts>\\n<nonce>\\n<METHOD>\\n<path?query>\\n<host>\\n<port>\\n<hash>\\n<ext>\\n

`mac = base64(HMAC-SHA256(key, normalized))`.  Every field is load-bearing:
drop the port and a request signed for one origin verifies against another;
drop the path and a GET of one collection authorizes a DELETE of the storage.

Two details this module is deliberate about:

* **Host and port come from `public_url`, not the `Host` header.**  The client
  signed the URL the tokenserver handed it, which is built from `public_url`;
  taking it from the request instead means any reverse proxy that rewrites
  `Host` silently breaks every signature.  Upstream reads actix's
  `ConnectionInfo` because it has no equivalent of `public_url` to consult.
* **The payload hash is verified when the client sends one.**  Upstream does
  not — neither the Rust server nor the Python one before it — so a request
  body there is covered only by whatever `hash` the client itself chose to
  claim.  A correct HAWK client computes it correctly by definition, so
  checking costs nothing and is the only thing that binds the body to the MAC.
  A request that omits `hash` is accepted with its body unauthenticated, which
  is what the specification says and what every real client relies on.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass

#: Clock skew allowed on `ts`. Upstream's own value, with the comment "client
#: timestamps tend to be all over the shop"; a year is not a typo.
MAX_SKEW_SECONDS = 52 * 7 * 24 * 60 * 60

#: `key="value"` pairs. HAWK defines no escaping, so a quote ends the value.
_ATTRIBUTE_RE = re.compile(r'(?P<key>[a-z]+)\s*=\s*"(?P<value>[^"\\]*)"')

_SCHEME = "hawk"


class HawkError(Exception):
    """A header we will not accept, for any reason. The caller answers 401."""


@dataclass(frozen=True, slots=True)
class HawkHeader:
    """The parsed `Authorization` header."""

    id: str
    ts: int
    nonce: str
    mac: str
    hash: str = ""
    ext: str = ""


def parse(header: str) -> HawkHeader:
    """`Hawk id="...", ts="...", nonce="...", mac="..."` -> `HawkHeader`."""
    scheme, _, rest = header.partition(" ")
    if scheme.lower() != _SCHEME or not rest.strip():
        raise HawkError("not a Hawk header")

    attributes = {m["key"]: m["value"] for m in _ATTRIBUTE_RE.finditer(rest)}
    missing = {"id", "ts", "nonce", "mac"} - attributes.keys()
    if missing:
        raise HawkError(f"missing Hawk attribute(s): {', '.join(sorted(missing))}")
    try:
        ts = int(attributes["ts"])
    except ValueError as exc:
        raise HawkError("non-integer Hawk ts") from exc
    return HawkHeader(
        id=attributes["id"],
        ts=ts,
        nonce=attributes["nonce"],
        mac=attributes["mac"],
        hash=attributes.get("hash", ""),
        ext=attributes.get("ext", ""),
    )


def normalized(
    header: HawkHeader, *, method: str, resource: str, host: str, port: int
) -> bytes:
    """The string the MAC is taken over. `resource` is the path *with* its query."""
    return (
        "\n".join(
            [
                "hawk.1.header",
                str(header.ts),
                header.nonce,
                method.upper(),
                resource,
                host.lower(),
                str(port),
                header.hash,
                header.ext,
            ]
        )
        + "\n"
    ).encode()


def mac(
    key: str, header: HawkHeader, *, method: str, resource: str, host: str, port: int
) -> str:
    """`base64(HMAC-SHA256(key, normalized))`, standard base64 with padding."""
    message = normalized(header, method=method, resource=resource, host=host, port=port)
    digest = hmac.new(key.encode("ascii"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def payload_hash(body: bytes, content_type: str) -> str:
    """`base64(sha256("hawk.1.payload\\n<type>\\n<body>\\n"))`.

    Only the media type takes part — `text/plain; charset=utf-8` normalizes to
    `text/plain` — because a client and a server that disagree about a
    `charset` parameter must still agree about the body.
    """
    media_type = content_type.partition(";")[0].strip().lower()
    prefix = f"hawk.1.payload\n{media_type}\n".encode()
    return base64.b64encode(hashlib.sha256(prefix + body + b"\n").digest()).decode("ascii")


def verify(
    header: HawkHeader,
    key: str,
    *,
    method: str,
    resource: str,
    host: str,
    port: int,
    now: int,
    body: bytes | None = None,
    content_type: str = "",
    max_skew: int = MAX_SKEW_SECONDS,
) -> None:
    """Raise `HawkError` unless this header authorizes this exact request."""
    if abs(now - header.ts) > max_skew:
        raise HawkError("Hawk ts outside the allowed skew")
    expected = mac(key, header, method=method, resource=resource, host=host, port=port)
    if not hmac.compare_digest(expected, header.mac):
        raise HawkError("bad Hawk MAC")
    if header.hash:
        if body is None:
            raise HawkError("Hawk hash on a request with no body to hash")
        if not hmac.compare_digest(payload_hash(body, content_type), header.hash):
            raise HawkError("bad Hawk payload hash")


__all__ = [
    "MAX_SKEW_SECONDS",
    "HawkError",
    "HawkHeader",
    "mac",
    "normalized",
    "parse",
    "payload_hash",
    "verify",
]
