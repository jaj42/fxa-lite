# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The two `.well-known` documents Firefox reads before anything else.

`identity.fxaccounts.autoconfig.uri` points at this origin and every other
endpoint is discovered from here, so a wrong base URL is a sign-in that fails
before a single API call. The version segments are the trap: Firefox appends
`/v1` to the auth, OAuth and profile bases, and `/1.0/sync/1.5` to the
tokenserver base, so none of them may carry it already.
"""

from conformance.client import AuthClient, decode_jwt
from conftest import EMAIL, PASSWORD, PUBLIC_URL


async def test_client_configuration(bearer_client: AuthClient) -> None:
    document = await bearer_client.client_configuration()
    assert document == {
        "auth_server_base_url": PUBLIC_URL,
        "oauth_server_base_url": PUBLIC_URL,
        "profile_server_base_url": f"{PUBLIC_URL}/profile",
        "sync_tokenserver_base_url": f"{PUBLIC_URL}/token",
        "pairing_server_base_uri": "ws://fxa.example.com",
    }


async def test_client_configuration_bases_carry_no_version_segment(
    bearer_client: AuthClient,
) -> None:
    document = await bearer_client.client_configuration()
    for key in ("auth_server_base_url", "oauth_server_base_url", "profile_server_base_url"):
        assert not document[key].endswith("/v1"), key
    assert not document["sync_tokenserver_base_url"].endswith("/1.0/sync/1.5")


async def test_the_advertised_endpoints_actually_answer(bearer_client: AuthClient) -> None:
    """The bases plus what Firefox appends have to reach real routes."""
    document = await bearer_client.client_configuration()
    auth = document["auth_server_base_url"].removeprefix(PUBLIC_URL)
    profile = document["profile_server_base_url"].removeprefix(PUBLIC_URL)
    assert "keys" in await bearer_client.raw_request("GET", f"{auth}/v1/jwks")
    response = await bearer_client.http.get(f"{profile}/v1/profile")
    # 401 rather than 404: the route exists and wants a token.
    assert response.status_code == 401


async def test_openid_configuration(bearer_client: AuthClient) -> None:
    document = await bearer_client.openid_configuration()
    assert document["issuer"] == PUBLIC_URL
    assert document["jwks_uri"] == f"{PUBLIC_URL}/v1/jwks"
    assert document["token_endpoint"] == f"{PUBLIC_URL}/v1/oauth/token"
    assert document["userinfo_endpoint"] == f"{PUBLIC_URL}/profile/v1/profile"
    assert document["revocation_endpoint"] == f"{PUBLIC_URL}/v1/oauth/destroy"


async def test_issuer_matches_the_tokens_we_sign(bearer_client: AuthClient) -> None:
    """A relier that checks `iss` against discovery must not be surprised."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD, scope="profile")
    _, claims = decode_jwt(grant.access_token)
    document = await bearer_client.openid_configuration()
    assert claims["iss"] == document["issuer"]


async def test_discovery_documents_are_cacheable(bearer_client: AuthClient) -> None:
    for path in ("fxa-client-configuration", "openid-configuration"):
        response = await bearer_client.http.get(f"/.well-known/{path}")
        assert response.headers["cache-control"] == "public, max-age=86400"
