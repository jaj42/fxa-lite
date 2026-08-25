"""HAWK verification, pinned to syncstorage-rs's own test fixture.

`syncserver/src/web/auth.rs` carries a complete, hand-built example: a master
secret, a tokenlib id minted from it, and two signed requests with their MACs.
Running it end to end — signing key, token signature, derived HAWK key, MAC —
is the only check that proves fxa-lite would accept a credential a real Sync
client presents, and would reject one it does not.

Everything else in this file is a mutation of that fixture: change one field
and the MAC must stop verifying, because every field is in the normalized
string for a reason.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TypedDict

import pytest

from fxa_lite.syncstorage import hawk
from fxa_lite.syncstorage.credentials import _exempt_from_expiry, parse_token
from fxa_lite.tokenserver import tokenlib
from vectors import load

VECTORS = load("hawk")
SECRET = VECTORS["master_secret"]
TOKEN_ID = VECTORS["token_id"]
REQUESTS = {case["name"]: case for case in VECTORS["requests"]}


class Request(TypedDict):
    method: str
    resource: str
    host: str
    port: int


def _request(case: dict) -> Request:
    return Request(
        method=case["method"],
        resource=case["resource"],
        host=case["host"],
        port=case["port"],
    )


def _header(case: dict) -> hawk.HawkHeader:
    return hawk.HawkHeader(
        id=TOKEN_ID, ts=case["ts"], nonce=case["nonce"], mac=case["mac"]
    )


def test_token_signature_and_claims_match_the_fixture():
    credentials = parse_token(TOKEN_ID, SECRET)
    expected = VECTORS["claims"]
    assert credentials.uid == expected["uid"]
    assert credentials.node == expected["node"]
    assert credentials.salt == expected["salt"]
    assert credentials.fxa_uid == expected["fxa_uid"]
    assert credentials.fxa_kid == expected["fxa_kid"]
    assert credentials.hashed_fxa_uid == expected["hashed_fxa_uid"]
    assert credentials.hashed_device_id == expected["hashed_device_id"]
    assert credentials.expires == round(expected["expires"])


def test_derived_key_matches_the_fixture():
    """The HAWK key storage recomputes. Wrong here and every MAC below fails."""
    assert tokenlib.derive_secret(TOKEN_ID, VECTORS["claims"]["salt"], SECRET) == (
        VECTORS["derived_key"]
    )


@pytest.mark.parametrize("name", sorted(REQUESTS))
def test_reference_macs_verify(name):
    case = REQUESTS[name]
    assert hawk.mac(VECTORS["derived_key"], _header(case), **_request(case)) == case["mac"]
    hawk.verify(
        _header(case), VECTORS["derived_key"], now=case["ts"], **_request(case)
    )


def test_a_token_signed_with_another_secret_is_rejected():
    with pytest.raises(hawk.HawkError):
        parse_token(TOKEN_ID, "wibble")


def test_a_tampered_signature_is_rejected():
    raw = bytearray(base64.urlsafe_b64decode(TOKEN_ID))
    raw[-1] ^= 0x01
    with pytest.raises(hawk.HawkError):
        parse_token(base64.urlsafe_b64encode(bytes(raw)).decode(), SECRET)


def test_a_tampered_payload_is_rejected():
    """The claims are what authorize the request, so they are what is signed."""
    raw = base64.urlsafe_b64decode(TOKEN_ID)
    claims = json.loads(raw[:-32])
    claims["uid"] = 2
    forged = json.dumps(claims).encode() + raw[-32:]
    with pytest.raises(hawk.HawkError):
        parse_token(base64.urlsafe_b64encode(forged).decode(), SECRET)


def test_a_truncated_token_is_rejected():
    with pytest.raises(hawk.HawkError):
        parse_token(base64.urlsafe_b64encode(b"short").decode(), SECRET)


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "POST"),
        ("resource", "/storage/1.5/1/storage/col3"),
        ("host", "localhost.com"),
        ("port", 5001),
    ],
)
def test_every_signed_field_is_signed(field, value):
    """Change any one of them and the MAC must stop matching."""
    case = REQUESTS["valid_header"]
    request = {**_request(case), field: value}
    with pytest.raises(hawk.HawkError):
        hawk.verify(_header(case), VECTORS["derived_key"], now=case["ts"], **request)


def test_the_query_string_is_part_of_the_resource():
    """`?commit=true` is the difference between staging and storing."""
    case = REQUESTS["valid_header"]
    request = {**_request(case), "resource": case["resource"] + "?commit=true"}
    with pytest.raises(hawk.HawkError):
        hawk.verify(_header(case), VECTORS["derived_key"], now=case["ts"], **request)


@pytest.mark.parametrize("field", ["ts", "nonce", "mac"])
def test_a_mutated_header_field_fails(field):
    case = REQUESTS["valid_header"]
    mutated = {"ts": case["ts"] + 1, "nonce": "0000", "mac": "A" * 44}[field]
    attributes: dict = {
        "id": TOKEN_ID,
        "ts": case["ts"],
        "nonce": case["nonce"],
        "mac": case["mac"],
        field: mutated,
    }
    header = hawk.HawkHeader(**attributes)
    with pytest.raises(hawk.HawkError):
        hawk.verify(header, VECTORS["derived_key"], now=case["ts"], **_request(case))


def test_a_stale_timestamp_is_rejected():
    case = REQUESTS["valid_header"]
    with pytest.raises(hawk.HawkError):
        hawk.verify(
            _header(case),
            VECTORS["derived_key"],
            now=case["ts"] + hawk.MAX_SKEW_SECONDS + 1,
            **_request(case),
        )


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer abc",
        'Hawk ts="1", nonce="x", mac="y"',
        'Hawk id="a", nonce="x", mac="y"',
        'Hawk id="a", ts="soon", nonce="x", mac="y"',
        "Hawk",
    ],
)
def test_unparseable_headers_are_rejected(header):
    with pytest.raises(hawk.HawkError):
        hawk.parse(header)


def test_optional_attributes_are_parsed():
    parsed = hawk.parse(
        'Hawk id="a", ts="1", nonce="n", mac="m", hash="h", ext="e"'
    )
    assert (parsed.hash, parsed.ext) == ("h", "e")


def test_the_payload_hash_covers_the_body():
    """Upstream never checks this; fxa-lite does. See `hawk.py`.

    The MAC alone cannot catch a swapped body, because the `hash` it covers is
    whatever the client claimed rather than what the server received.
    """
    body = b'{"id":"a","payload":"x"}'
    digest = hawk.payload_hash(body, "application/json")
    header = hawk.HawkHeader(id=TOKEN_ID, ts=1, nonce="n", mac="", hash=digest)
    signed = hawk.HawkHeader(
        id=header.id,
        ts=header.ts,
        nonce=header.nonce,
        mac=hawk.mac(
            VECTORS["derived_key"],
            header,
            method="PUT",
            resource="/storage/1.5/1/storage/col/a",
            host="localhost",
            port=5000,
        ),
        hash=digest,
    )
    request = Request(
        method="PUT", resource="/storage/1.5/1/storage/col/a", host="localhost", port=5000
    )
    hawk.verify(
        signed,
        VECTORS["derived_key"],
        now=1,
        body=body,
        content_type="application/json",
        **request,
    )
    with pytest.raises(hawk.HawkError):
        hawk.verify(
            signed,
            VECTORS["derived_key"],
            now=1,
            body=b'{"id":"a","payload":"tampered"}',
            content_type="application/json",
            **request,
        )


def test_the_payload_hash_ignores_content_type_parameters():
    """`text/plain; charset=utf-8` and `text/plain` must hash the same."""
    body = b"hello"
    assert hawk.payload_hash(body, "text/plain; charset=utf-8") == hawk.payload_hash(
        body, "TEXT/PLAIN"
    )


@pytest.mark.parametrize(
    ("path", "exempt"),
    [
        ("/1.5/123/info/collections", True),
        # The writable storage route shares the suffix: a BSO `collections` in
        # a collection `info`, which must not be reachable on a dead token.
        ("/1.5/123/storage/info/collections", False),
        ("/1.5/123/storage/bookmarks/abc", False),
        # A trailing slash leaves a fifth, empty segment. Upstream asserts this
        # case too, and only the leading slash is stripped here so that it holds
        # whether or not the router still redirects a trailing slash first.
        ("/1.5/123/info/collections/", False),
        ("/1.5/123/info/collections/extra", False),
        ("/1.5//info/collections", False),
        ("/1.6/123/info/collections", False),
        ("/info/collections", False),
    ],
)
def test_only_info_collections_survives_expiry(path, exempt):
    """`is_info_collections_path`, assertion for assertion. See `auth.rs`."""
    assert _exempt_from_expiry(path) is exempt


# --------------------------------------------------------------------------
# The specification's own worked examples.
#
# Everything above pins fxa-lite to syncstorage-rs, which proves the two agree
# but not that either is right: a normalized string with the wrong field order
# verifies perfectly against a fixture built by the same wrong code. The HAWK
# specification (`resources/hawk_api.md`) publishes three known answers — a MAC
# with no payload hash, a payload hash, and a MAC that covers one — computed by
# the reference JavaScript implementation. They are the only cross-implementation
# check of the normalized string that exists, and nothing here derives from them.
# --------------------------------------------------------------------------

SPEC = load("hawk_spec")
SPEC_KEY = SPEC["credentials"]["key"]
SPEC_PAYLOAD = SPEC["payload"]
SPEC_REQUESTS = {case["name"]: case for case in SPEC["requests"]}


def _spec_header(case: dict) -> hawk.HawkHeader:
    return hawk.HawkHeader(
        id=SPEC["credentials"]["id"],
        ts=case["ts"],
        nonce=case["nonce"],
        mac=case["mac"],
        hash=case["hash"],
        ext=case["ext"],
    )


@pytest.mark.parametrize("name", sorted(SPEC_REQUESTS))
def test_the_specification_normalized_string_is_ours(name):
    """Byte for byte, including the empty `hash` line and the trailing newline."""
    case = SPEC_REQUESTS[name]
    normalized = hawk.normalized(_spec_header(case), **_request(case))
    assert normalized == case["normalized"].encode()


@pytest.mark.parametrize("name", sorted(SPEC_REQUESTS))
def test_the_specification_macs_verify(name):
    case = SPEC_REQUESTS[name]
    header = _spec_header(case)
    assert hawk.mac(SPEC_KEY, header, **_request(case)) == case["mac"]
    signed_body = bool(case["hash"])
    hawk.verify(
        header,
        SPEC_KEY,
        now=case["ts"],
        body=SPEC_PAYLOAD["body"].encode() if signed_body else None,
        content_type=SPEC_PAYLOAD["content_type"] if signed_body else "",
        **_request(case),
    )


@pytest.mark.parametrize("name", sorted(SPEC_REQUESTS))
def test_the_specification_headers_parse_to_their_artifacts(name):
    """The header lines as the specification prints them, attributes and all."""
    case = SPEC_REQUESTS[name]
    assert hawk.parse(case["header"]) == _spec_header(case)


def test_the_specification_payload_hash():
    digest = hawk.payload_hash(SPEC_PAYLOAD["body"].encode(), SPEC_PAYLOAD["content_type"])
    assert digest == SPEC_PAYLOAD["hash"]
    # And the string that was hashed, which is what a field-order slip moves.
    hashed = hashlib.sha256(SPEC_PAYLOAD["hashed"].encode()).digest()
    assert base64.b64encode(hashed).decode() == SPEC_PAYLOAD["hash"]
