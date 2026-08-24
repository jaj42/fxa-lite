"""The client registry: what ships built in, and what config may change about it."""

import pytest

from fxa_lite.config import ConfigError, from_dict
from fxa_lite.oauth.clients import (
    FENIX_CLIENT_ID,
    FIREFOX_DESKTOP_CLIENT_ID,
    FIREFOX_IOS_CLIENT_ID,
    OLDSYNC_SCOPE,
    WEBCHANNEL_REDIRECT,
    Registry,
)

PUBLIC_URL = "https://fxa.example.com"


def _registry(**overrides) -> Registry:
    return Registry(from_dict({"public_url": PUBLIC_URL, **overrides}).clients)


def test_the_three_browsers_ship_built_in() -> None:
    registry = _registry()
    assert {client.id for client in registry} == {
        FIREFOX_DESKTOP_CLIENT_ID,
        FENIX_CLIENT_ID,
        FIREFOX_IOS_CLIENT_ID,
    }


def test_browsers_may_have_the_sync_key_and_are_public() -> None:
    desktop = _registry().get(FIREFOX_DESKTOP_CLIENT_ID)
    assert desktop is not None
    assert desktop.allowed_scopes.contains(OLDSYNC_SCOPE)
    # Public means PKCE is mandatory and no client secret exists to leak.
    assert desktop.public_client
    assert desktop.trusted


def test_redirects_include_the_webchannel_sentinel_and_the_success_page() -> None:
    desktop = _registry().get(FIREFOX_DESKTOP_CLIENT_ID)
    assert desktop is not None
    assert desktop.redirect_uris == (
        WEBCHANNEL_REDIRECT,
        f"{PUBLIC_URL}/oauth/success/{FIREFOX_DESKTOP_CLIENT_ID}",
    )
    assert desktop.redirect_uri == WEBCHANNEL_REDIRECT


def test_lookup_is_case_insensitive() -> None:
    assert _registry().get(FIREFOX_DESKTOP_CLIENT_ID.upper()) is not None


def test_config_can_add_a_client() -> None:
    registry = _registry(
        clients=[
            {
                "id": "00112233445566aa",
                "name": "Thunderbird",
                "redirect_uris": ["https://mail.example.com/oauth"],
                "allowed_scopes": "https://identity.thunderbird.net/apps/sync",
            }
        ]
    )
    assert len(registry) == 4
    added = registry.get("00112233445566aa")
    assert added is not None
    assert added.name == "Thunderbird"
    assert added.allowed_scopes.contains("https://identity.thunderbird.net/apps/sync")


def test_config_replaces_a_built_in_wholesale() -> None:
    """Not merged: a half-overridden client is how a scope gets granted by accident."""
    registry = _registry(
        clients=[
            {
                "id": FIREFOX_DESKTOP_CLIENT_ID,
                "name": "Firefox",
                "redirect_uris": ["https://elsewhere.example.com/callback"],
                "allowed_scopes": "profile",
            }
        ]
    )
    desktop = registry.get(FIREFOX_DESKTOP_CLIENT_ID)
    assert desktop is not None
    assert len(registry) == 3
    assert desktop.redirect_uris == ("https://elsewhere.example.com/callback",)
    assert not desktop.allowed_scopes.contains(OLDSYNC_SCOPE)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({"name": "x", "redirect_uris": ["https://x/"]}, id="no-id"),
        pytest.param(
            {"id": "nothex", "name": "x", "redirect_uris": ["https://x/"]}, id="bad-id"
        ),
        pytest.param({"id": "00112233445566aa", "name": "x"}, id="no-redirects"),
        pytest.param(
            {"id": "00112233445566aa", "name": "x", "redirect_uris": []}, id="empty-redirects"
        ),
        pytest.param(
            {"id": "00112233445566aa", "name": "x", "redirect_uris": ["https://x/"], "typo": 1},
            id="unknown-key",
        ),
        pytest.param(
            {
                "id": "00112233445566aa",
                "name": "x",
                "redirect_uris": ["https://x/"],
                "trusted": "yes",
            },
            id="non-boolean-flag",
        ),
    ],
)
def test_malformed_client_entries_are_rejected(entry) -> None:
    with pytest.raises(ConfigError):
        from_dict({"public_url": PUBLIC_URL, "clients": [entry]})


def test_clients_must_be_an_array_of_tables() -> None:
    with pytest.raises(ConfigError):
        from_dict({"public_url": PUBLIC_URL, "clients": {"id": "00112233445566aa"}})
