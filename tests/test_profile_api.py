# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`/profile/v1/*` — what an access token is allowed to learn about an account.

The interesting property is negative: a token scoped to `profile:uid` must come
away knowing the uid and nothing else. Upstream enforces that by routing each
field through a separate scope-gated endpoint; here the gating is inline, so it
is worth testing field by field.
"""

import httpx
import pytest

from conformance.client import AuthClient, ClientError
from conftest import EMAIL, PASSWORD, PUBLIC_URL


async def _token(client: AuthClient, scope: str) -> str:
    """Sign in and come back with an access token carrying exactly `scope`."""
    try:
        await client.sign_up(EMAIL, PASSWORD)
    except ClientError as exc:
        if exc.errno != 101:
            raise
    grant = await client.sync_sign_in(EMAIL, PASSWORD, scope=scope)
    return grant.access_token


async def test_profile_reports_everything_the_scope_allows(bearer_client: AuthClient) -> None:
    token = await _token(bearer_client, "profile")
    profile = await bearer_client.profile(token)
    assert profile["email"] == EMAIL
    assert profile["amrValues"] == ["pwd", "email"]
    assert profile["twoFactorAuthentication"] is False
    assert profile["metricsEnabled"] is False
    # No avatar store, so the picture is always the monogram route — but the
    # key is present, because Firefox for Android's parser requires a string
    # there and drops the whole document without one.
    assert profile["avatar"] == f"{PUBLIC_URL}/profile/v1/avatar/{EMAIL[0].lower()}"
    assert profile["avatarDefault"] is True
    assert "displayName" not in profile


async def test_the_document_carries_every_field_the_mobile_client_requires(
    bearer_client: AuthClient,
) -> None:
    """`ProfileResponse` in `application-services` is a Rust struct, and every
    field but `displayName` is required.  `serde` rejects the whole document if
    one is missing, so the phone's account has no profile — and Fenix's menu
    reads a missing profile as "not signed in" and offers to sign in to the
    account it is syncing with.  This is the regression guard for that."""
    profile = await bearer_client.profile(await _token(bearer_client, "profile"))
    assert isinstance(profile["uid"], str)
    assert isinstance(profile["email"], str)
    assert isinstance(profile["avatar"], str)
    assert isinstance(profile["avatarDefault"], bool)


async def test_uid_only_token_learns_only_the_uid(bearer_client: AuthClient) -> None:
    token = await _token(bearer_client, "profile:uid")
    profile = await bearer_client.profile(token)
    assert "uid" in profile
    assert "email" not in profile
    assert "locale" not in profile
    assert "amrValues" not in profile
    # Both avatar keys or neither: they are one internal call upstream, and
    # this token would not be allowed to make it.
    assert "avatar" not in profile
    assert "avatarDefault" not in profile


async def test_avatar_without_email_scope_gives_away_no_initial(
    bearer_client: AuthClient,
) -> None:
    """The monogram is a fact about the address, so a token that may not see
    the address does not get to read the first letter of it off the URL."""
    profile = await bearer_client.profile(await _token(bearer_client, "profile:avatar"))
    assert profile["avatar"] == f"{PUBLIC_URL}/profile/v1/avatar/default"
    assert profile["avatarDefault"] is True
    assert "email" not in profile


async def test_the_monogram_is_served_and_needs_no_token(http: httpx.AsyncClient) -> None:
    """An `<img>` in browser chrome has no access token to spend on this."""
    response = await http.get("/profile/v1/avatar/j")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert ">J<" in response.text


async def test_a_monogram_that_is_not_one_letter_renders_a_question_mark(
    http: httpx.AsyncClient,
) -> None:
    """Upstream's own rule, and what makes `default` a name rather than a case."""
    for path in ("/profile/v1/avatar/default", "/profile/v1/avatar/%C3%A9"):
        response = await http.get(path)
        assert response.status_code == 200
        assert ">?<" in response.text


async def test_sub_appears_only_for_openid(bearer_client: AuthClient) -> None:
    profile = await bearer_client.profile(await _token(bearer_client, "profile"))
    assert "sub" not in profile
    profile = await bearer_client.profile(await _token(bearer_client, "openid profile"))
    assert profile["sub"] == profile["uid"]


async def test_email_endpoint(bearer_client: AuthClient) -> None:
    token = await _token(bearer_client, "profile:email")
    assert await bearer_client.profile(token, "/email") == {"email": EMAIL}


async def test_uid_endpoint(bearer_client: AuthClient) -> None:
    token = await _token(bearer_client, "profile:uid")
    result = await bearer_client.profile(token, "/uid")
    assert len(result["uid"]) == 32


async def test_display_name_is_always_empty(bearer_client: AuthClient) -> None:
    """204, the same answer the reference gives an account that never set one."""
    token = await _token(bearer_client, "profile:display_name")
    assert await bearer_client.profile(token, "/display_name") is None


async def test_insufficient_scope_is_forbidden(bearer_client: AuthClient) -> None:
    token = await _token(bearer_client, "profile:uid")
    with pytest.raises(ClientError) as caught:
        await bearer_client.profile(token, "/email")
    assert caught.value.status == 403
    assert caught.value.errno == 100


async def test_missing_token_is_unauthorized(bearer_client: AuthClient) -> None:
    with pytest.raises(ClientError) as caught:
        await bearer_client.raw_request("GET", "/profile/v1/profile")
    assert caught.value.status == 401
    assert caught.value.errno == 100


async def test_a_session_token_is_not_an_access_token(bearer_client: AuthClient) -> None:
    """The two are both "Bearer" on the wire; only one verifies as a JWT."""
    account = await bearer_client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError) as caught:
        await bearer_client.profile(account["sessionToken"])
    assert caught.value.status == 401


async def test_a_token_for_a_deleted_account_is_unauthorized(
    bearer_client: AuthClient, db
) -> None:
    token = await _token(bearer_client, "profile")
    db.delete_account((await bearer_client.profile(token))["uid"])
    with pytest.raises(ClientError) as caught:
        await bearer_client.profile(token)
    assert caught.value.status == 401
