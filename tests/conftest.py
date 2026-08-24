"""Fixtures shared by the HTTP-level tests.

The app is driven in-process through `httpx.ASGITransport` — no socket, no
uvicorn — against a shared-cache in-memory database, so a full sign-up/sign-in
round trip costs whatever scrypt costs and nothing more.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from conformance.client import AuthClient
from fxa_lite.app import create_app
from fxa_lite.config import Config, from_dict
from fxa_lite.db import Database, open_database

PASSWORD = "correct horse battery staple"
EMAIL = "sync-user@example.com"


@pytest.fixture
def config() -> Config:
    return from_dict({"public_url": "http://fxa.example.com"})


@pytest.fixture
def db() -> Iterator[Database]:
    database = open_database(":memory:")
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def app(config: Config, db: Database):
    return create_app(config, db=db)


@pytest.fixture
async def http(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://fxa.example.com") as client:
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
