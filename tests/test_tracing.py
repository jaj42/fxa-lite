# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Request tracing, and above all what it refuses to write down.

The tests that matter here are the redaction ones. A trace that leaks a
`sessionToken` is worse than no trace at all: it turns a debugging aid into a
credential store, and the log outlives the session it describes.
"""

import json
import logging

import pytest

from conformance.client import AuthClient, ClientError
from conftest import EMAIL, PASSWORD
from fxa_lite import tracing


@pytest.fixture
def traced(caplog: pytest.LogCaptureFixture):
    """Turn the `fxa_lite` logger up to DEBUG for one test."""
    caplog.set_level(logging.DEBUG, logger=tracing.LOGGER_NAME)
    return caplog


# -- redaction ---------------------------------------------------------------


def test_a_credential_becomes_a_prefix_and_a_length() -> None:
    redacted = tracing.redact({"authPW": "a" * 64})
    assert redacted == {"authPW": "aaaaaaaa…(64 chars)"}


def test_a_short_secret_is_not_given_away_by_its_length() -> None:
    """Eight characters of an eight-character secret would be all of it."""
    assert tracing.redact({"token": "short"}) == {"token": "…"}


def test_redaction_reaches_into_nested_documents() -> None:
    document = {"outer": {"items": [{"sessionToken": "b" * 64, "uid": "abc"}]}}
    redacted = tracing.redact(document)
    inner = redacted["outer"]["items"][0]
    assert inner["sessionToken"] == "bbbbbbbb…(64 chars)"
    # Everything that is not a credential survives, or the trace is useless.
    assert inner["uid"] == "abc"


def test_a_non_secret_field_is_left_alone_however_long() -> None:
    value = "https://identity.mozilla.com/apps/oldsync profile openid"
    assert tracing.redact({"scope": value}) == {"scope": value}


def test_a_query_string_credential_is_redacted() -> None:
    """An authorization code rides in a query string on the way back."""
    rendered = tracing.render_query(b"code=" + b"c" * 64 + b"&state=abcd")
    assert "c" * 64 not in rendered
    assert "state=abcd" in rendered


def test_an_authorization_header_keeps_its_scheme_and_loses_its_token() -> None:
    assert tracing.render_authorization("Hawk id=\"" + "d" * 64 + "\"").startswith("Hawk ")
    assert "d" * 64 not in tracing.render_authorization('Hawk id="' + "d" * 64 + '"')
    assert tracing.render_authorization(None) == "none"


def test_a_body_that_is_not_json_is_described_by_its_size() -> None:
    assert tracing.render_body(b"\x00\x01\x02") == "<3 bytes, not JSON>"
    assert tracing.render_body(b"") == "(empty)"


def test_a_large_body_is_truncated() -> None:
    rendered = tracing.render_body(json.dumps({"scope": "x" * 8192}).encode())
    assert len(rendered) < 8192
    assert rendered.endswith("chars)")


# -- the middleware ----------------------------------------------------------


async def test_nothing_is_traced_below_debug(
    bearer_client: AuthClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=tracing.LOGGER_NAME)
    await bearer_client.sign_up(EMAIL, PASSWORD)
    assert not [record for record in caplog.records if record.name == tracing.LOGGER_NAME]


async def test_a_traced_request_records_both_bodies(
    bearer_client: AuthClient, traced: pytest.LogCaptureFixture
) -> None:
    await bearer_client.sign_up(EMAIL, PASSWORD)
    await bearer_client.sign_in(EMAIL, PASSWORD)
    messages = [record.getMessage() for record in traced.records]
    login = [line for line in messages if "/v1/account/login" in line]
    assert login, messages
    # The request's own fields, and the response's — the pair is the point.
    assert "email" in login[0]
    assert "uid" in login[0]
    assert "-> 200" in login[0]


async def test_a_traced_sign_in_never_writes_the_password_verifier(
    bearer_client: AuthClient, traced: pytest.LogCaptureFixture
) -> None:
    """The one that would matter: `authPW` is the password, stretched."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    account = await bearer_client.sign_in(EMAIL, PASSWORD, keys=True)
    written = "\n".join(record.getMessage() for record in traced.records)
    assert account["sessionToken"] not in written
    assert account["keyFetchToken"] not in written
    assert PASSWORD not in written


async def test_a_traced_failure_records_the_error_body(
    bearer_client: AuthClient, traced: pytest.LogCaptureFixture
) -> None:
    """The case the one-off tap was written for: why was this a 400?"""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError):
        await bearer_client.sign_in(EMAIL, "wrong-password-entirely")
    messages = [record.getMessage() for record in traced.records]
    failures = [line for line in messages if "-> 400" in line]
    assert failures
    assert "errno" in failures[0]
