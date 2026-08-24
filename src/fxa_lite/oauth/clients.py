"""The OAuth client registry.

Upstream this is a MySQL table maintained by an admin panel.  fxa-lite has a
fixed, small cast — the three Firefox browsers — so the registry is config, and
the built-ins are enough to sign in without writing any.

Every client here is a **public** client: a browser cannot keep a secret, so
there is no `client_secret` anywhere in this file and PKCE is mandatory
instead.  That is not a simplification of the reference, it is what the
reference does for these three ids (`config/dev.json`, `oauthServer.clients`).

`trusted` and `canGrant` are copied from upstream too.  `trusted` widens the
scopes a client may ask for beyond the `profile:*` handful; `canGrant` allows
the direct `fxa-credentials` grant.  Both are true for the browsers, which is
why Firefox can ask for `apps/oldsync` at all.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .scopes import ScopeSet

#: `OAUTH_SCOPE_OLD_SYNC` — the scope that carries the Sync encryption key.
OLDSYNC_SCOPE = "https://identity.mozilla.com/apps/oldsync"
#: Grants the holder a fresh session token at `/v1/oauth/token`. Not implemented
#: here (nothing fxa-lite serves needs it), but listed so a client that asks for
#: it is refused on the scope, not silently granted something inert.
SESSION_SCOPE = "https://identity.mozilla.com/tokens/session"
ECOSYSTEM_TELEMETRY_SCOPE = "https://identity.mozilla.com/ids/ecosystem_telemetry"

#: `urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel` — not a URL at all. The
#: browser is both the client and the user agent, so the "redirect" is a
#: WebChannel message rather than a navigation.
WEBCHANNEL_REDIRECT = "urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel"

FIREFOX_DESKTOP_CLIENT_ID = "5882386c6d801776"
FENIX_CLIENT_ID = "a2270f727f45f648"
FIREFOX_IOS_CLIENT_ID = "1b1a3e44c54fbb58"

#: Scopes that carry a derived key. Only these appear in `/account/scoped-key-data`
#: and only these make a `keys_jwe` meaningful (`oauthServer.scopes` upstream).
KEY_BEARING_SCOPES = frozenset(
    {
        OLDSYNC_SCOPE,
        ECOSYSTEM_TELEMETRY_SCOPE,
        "https://identity.thunderbird.net/apps/sync",
    }
)

#: `oauthServer.authorization.serviceScopes` — what `service=sync` resolves to
#: when a browser omits `scope=` entirely (ADR 0049).
SERVICE_SCOPES: dict[str, tuple[str, ...]] = {
    "sync": (OLDSYNC_SCOPE, "profile"),
}
#: Added to a resolved service scope set when the request carries `keys_jwe`,
#: i.e. the user typed their password and the client wrapped scoped keys.
KEYS_CONDITIONAL_SCOPE = OLDSYNC_SCOPE


class ClientError(ValueError):
    """Raised for a malformed client definition in the config file."""


@dataclass(frozen=True, slots=True)
class Client:
    id: str
    name: str
    #: Upstream stores these comma-separated in one column; an authorization
    #: request must match one of them exactly, no pattern matching.
    redirect_uris: tuple[str, ...]
    allowed_scopes: ScopeSet
    trusted: bool = True
    can_grant: bool = True
    public_client: bool = True
    image_uri: str = ""

    @property
    def redirect_uri(self) -> str:
        """The default, used when a request omits `redirect_uri`."""
        return self.redirect_uris[0]


class Registry:
    """The clients this server will issue tokens to, keyed by lowercase id."""

    def __init__(self, clients: Iterable[Client]) -> None:
        self._clients = {client.id: client for client in clients}

    def get(self, client_id: str) -> Client | None:
        return self._clients.get(client_id.lower())

    def __iter__(self) -> Iterator[Client]:
        return iter(self._clients.values())

    def __len__(self) -> int:
        return len(self._clients)


def default_clients(public_url: str) -> list[Client]:
    """The three browsers, with the redirects the reference registers for them.

    Both forms are accepted for each: the WebChannel sentinel, used when the
    browser drives the flow itself, and `<public_url>/oauth/success/<id>`, the
    page the mobile browsers watch for.
    """
    return [
        _browser(FIREFOX_DESKTOP_CLIENT_ID, "Firefox", public_url),
        _browser(FENIX_CLIENT_ID, "Fenix", public_url),
        _browser(FIREFOX_IOS_CLIENT_ID, "Firefox for iOS", public_url),
    ]


def _browser(client_id: str, name: str, public_url: str) -> Client:
    return Client(
        id=client_id,
        name=name,
        redirect_uris=(WEBCHANNEL_REDIRECT, f"{public_url}/oauth/success/{client_id}"),
        allowed_scopes=ScopeSet.from_array(
            [OLDSYNC_SCOPE, SESSION_SCOPE, ECOSYSTEM_TELEMETRY_SCOPE]
        ),
    )


def build(public_url: str, overrides: list[dict[str, object]]) -> tuple[Client, ...]:
    """Built-in clients, plus whatever the config file adds or replaces.

    An entry whose `id` matches a built-in replaces it wholesale rather than
    merging: a half-overridden client — new redirect, inherited scopes — is the
    kind of thing that works in testing and grants too much in production.
    """
    clients = {client.id: client for client in default_clients(public_url)}
    for entry in overrides:
        client = _from_config(entry)
        clients[client.id] = client
    return tuple(clients.values())


_KNOWN_KEYS = {
    "id",
    "name",
    "redirect_uris",
    "allowed_scopes",
    "trusted",
    "can_grant",
    "public_client",
    "image_uri",
}


def _from_config(entry: dict[str, object]) -> Client:
    unknown = sorted(set(entry) - _KNOWN_KEYS)
    if unknown:
        raise ClientError(f"unknown key(s) in [[clients]]: {', '.join(unknown)}")
    client_id = _string(entry, "id").lower()
    if len(client_id) != 16 or not all(character in "0123456789abcdef" for character in client_id):
        raise ClientError(f"clients.id must be 16 hex characters, got {client_id!r}")
    redirects = entry.get("redirect_uris")
    if not isinstance(redirects, list) or not redirects:
        raise ClientError(f"clients.redirect_uris is required for {client_id}")
    if not all(isinstance(uri, str) and uri for uri in redirects):
        raise ClientError(f"clients.redirect_uris must be non-empty strings for {client_id}")
    return Client(
        id=client_id,
        name=_string(entry, "name"),
        redirect_uris=tuple(redirects),
        allowed_scopes=ScopeSet.from_string(_string(entry, "allowed_scopes", default="")),
        trusted=_flag(entry, "trusted", client_id, default=True),
        can_grant=_flag(entry, "can_grant", client_id, default=True),
        # Defaulting to public is the safe direction: a public client is
        # required to prove PKCE, a confidential one would be trusted on a
        # secret fxa-lite has no way to store or rotate.
        public_client=_flag(entry, "public_client", client_id, default=True),
        image_uri=_string(entry, "image_uri", default=""),
    )


def _string(entry: dict[str, object], key: str, default: str | None = None) -> str:
    value = entry.get(key, default)
    if not isinstance(value, str):
        raise ClientError(f"clients.{key} must be a string")
    return value


def _flag(entry: dict[str, object], key: str, client_id: str, *, default: bool) -> bool:
    value = entry.get(key, default)
    if not isinstance(value, bool):
        raise ClientError(f"clients.{key} must be a boolean for {client_id}")
    return value
