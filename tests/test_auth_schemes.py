# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Both Authorization schemes, and what happens when neither is usable.

The load-bearing claim here is the one from the plan: HAWK MACs are parsed and
thrown away, exactly as `lib/routes/auth-schemes/hawk-fxa-token.js` does. A
server that verified them would reject clients the reference accepts.
"""

from __future__ import annotations

import pytest

from conformance.client import AuthClient, ClientError, bearer_header, derive_token_credentials
from conftest import EMAIL, PASSWORD


async def test_both_schemes_authenticate_the_same_token(
    bearer_client: AuthClient,
) -> None:
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    token = account["sessionToken"]

    bearer_client.scheme = "bearer"
    from_bearer = await bearer_client.session_status(token)
    bearer_client.scheme = "hawk"
    from_hawk = await bearer_client.session_status(token)
    assert from_bearer == from_hawk


async def test_a_nonsense_hawk_mac_is_accepted(bearer_client: AuthClient) -> None:
    """Deliberate: today's Mozilla server does not verify the MAC either, and the
    id it does check is 32 bytes of CSPRNG output."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    identifier = derive_token_credentials(account["sessionToken"], "sessionToken").id
    response = await bearer_client.http.get(
        "/v1/session/status",
        headers={"authorization": f'Hawk id="{identifier}", ts="1", nonce="x", mac="not-a-mac"'},
    )
    assert response.status_code == 200
    assert response.json()["uid"] == account["uid"]


async def test_a_missing_header_is_rejected(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.request("GET", "/session/status")
    assert caught.value.status == 401
    assert caught.value.errno == 110


@pytest.mark.parametrize(
    "header",
    [
        "Basic dXNlcjpwYXNz",
        "Bearer " + "a" * 64,  # An OAuth refresh token, not a session token.
        "Bearer fxk_" + "a" * 64,  # Right shape, wrong token kind.
        'Hawk id="short"',
        "Hawk",
        "Bearer fxs_" + "A" * 64,  # Uppercase hex: the reference's regex is strict.
    ],
)
async def test_unusable_headers_are_rejected(bearer_client: AuthClient, header: str) -> None:
    response = await bearer_client.http.get(
        "/v1/session/status", headers={"authorization": header}
    )
    assert response.status_code == 401
    assert response.json()["errno"] == 110


async def test_an_oversized_header_is_rejected(bearer_client: AuthClient) -> None:
    response = await bearer_client.http.get(
        "/v1/session/status", headers={"authorization": "Hawk " + "x" * 5000}
    )
    assert response.status_code == 401


async def test_an_unknown_token_id_is_rejected(bearer_client: AuthClient) -> None:
    response = await bearer_client.http.get(
        "/v1/session/status", headers=bearer_header("11" * 32, "sessionToken")
    )
    assert response.status_code == 401
    assert response.json()["errno"] == 110


async def test_a_session_token_cannot_fetch_keys(bearer_client: AuthClient) -> None:
    """The prefixes exist so the two credentials cannot be confused for each other."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD, keys=True)
    response = await bearer_client.http.get(
        "/v1/account/keys",
        headers=bearer_header(account["sessionToken"], "sessionToken"),
    )
    assert response.status_code == 401


async def test_the_error_envelope_shape(bearer_client: AuthClient) -> None:
    """Clients branch on `errno`; every field around it is part of the contract too."""
    response = await bearer_client.http.get("/v1/session/status")
    body = response.json()
    assert set(body) >= {"code", "errno", "error", "message", "info"}
    assert body["code"] == 401
    assert body["error"] == "Unauthorized"
    assert body["info"].startswith("https://")


async def test_an_unknown_endpoint_answers_in_the_same_envelope(
    bearer_client: AuthClient,
) -> None:
    response = await bearer_client.http.get("/v1/nope")
    assert response.status_code == 404
    assert response.json()["errno"] == 116


async def test_a_malformed_payload_is_a_parameter_error(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.request(
            "POST", "/account/login", {"email": EMAIL, "authPW": "not-hex"}
        )
    assert caught.value.errno == 107


async def test_an_unknown_payload_field_is_rejected(bearer_client: AuthClient) -> None:
    """joi strips unknown keys; we refuse them, so a typo fails loudly instead of
    quietly doing nothing."""
    with pytest.raises(ClientError) as caught:
        await bearer_client.request(
            "POST", "/account/login", {"email": EMAIL, "authPW": "ab" * 32, "authPw": "typo"}
        )
    assert caught.value.errno == 107


async def test_defaults_routes(bearer_client: AuthClient) -> None:
    assert (await bearer_client.http.get("/__heartbeat__")).status_code == 200
    assert (await bearer_client.http.get("/__lbheartbeat__")).status_code == 200
    assert "version" in (await bearer_client.http.get("/__version__")).json()
    assert (await bearer_client.http.get("/config")).json() == {
        "contentUrl": "http://fxa.example.com"
    }
