"""Fixtures shared by the HTTP-level tests.

The app is driven in-process through `httpx.ASGITransport` — no socket, no
uvicorn — against a shared-cache in-memory database, so a full sign-up/sign-in
round trip costs whatever scrypt costs and nothing more.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from conformance.client import AuthClient, TokenserverClient
from fxa_lite.app import create_app
from fxa_lite.config import Config, from_dict
from fxa_lite.crypto import jose
from fxa_lite.db import Database, open_database
from fxa_lite.oauth.keys import SigningKeys

PASSWORD = "correct horse battery staple"
EMAIL = "sync-user@example.com"
PUBLIC_URL = "http://fxa.example.com"


@pytest.fixture
def config() -> Config:
    """The app under test, with `/account/create` open.

    `[security] open_registration` defaults to *false* — see `auth/account.py` —
    but the conformance client signs up over HTTP exactly as the reference
    client does, and that round trip is what most of these tests are about.
    The gate itself is tested in `test_security.py`, against the default.
    """
    return from_dict({"public_url": PUBLIC_URL, "security": {"open_registration": True}})


@pytest.fixture(scope="session")
def signing_keys() -> SigningKeys:
    """One RSA key for the whole run.

    Generating 2048 bits per test would dominate the suite's runtime, and no
    test cares *which* key signs — only that the same one verifies.
    """
    key = jose.generate_signing_key()
    jwk = jose.private_key_to_jwk(key)
    return SigningKeys(
        private=key,
        kid=jwk["kid"],
        verifiers={jwk["kid"]: key.public_key()},
        jwks={"keys": [jose.public_jwk(jwk)]},
    )


@pytest.fixture
def db() -> Iterator[Database]:
    database = open_database(":memory:")
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def app(config: Config, db: Database, signing_keys: SigningKeys):
    return create_app(config, db=db, signing_keys=signing_keys)


@pytest.fixture
async def http(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
        yield client


@pytest.fixture(params=["bearer", "hawk"])
def scheme(request: pytest.FixtureRequest) -> str:
    """Every authenticated test runs twice, once per Authorization scheme."""
    return request.param


@pytest.fixture
def client(http: httpx.AsyncClient, scheme: str) -> AuthClient:
    return AuthClient(http, scheme=scheme)


@pytest.fixture
def bearer_client(http: httpx.AsyncClient) -> AuthClient:
    """For tests where the scheme is irrelevant and running twice buys nothing."""
    return AuthClient(http, scheme="bearer")


@pytest.fixture
def tokenserver(http: httpx.AsyncClient) -> TokenserverClient:
    return TokenserverClient(http)


@pytest.fixture
def tokenserver_secret(app) -> str:
    """What the storage tier would have been told out of band.

    Reading it off the app is not a shortcut around the protocol: in phase 6
    the reader of these tokens is this same process, and every test that uses
    it re-derives the token from scratch rather than asking fxa-lite anything.
    """
    return app.state.tokenserver_secret
