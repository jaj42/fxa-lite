"""Phase 10: the audit's fixes, and pins under what it only confirmed.

Two kinds of test live here.  The first half is the fixes — a body cap, a
registration gate, a failed-password throttle, redaction, file modes, headers —
each one written against the finding it closes.  The second half is the part
`AUDIT.md` lists as *confirm and pin*: properties that were already true when
the audit read them, and that nothing in the code says out loud.  A pin is
cheap and a silent regression in any of them is a credential.

The findings are numbered as `AUDIT.md` numbers them.
"""

from __future__ import annotations

import json
import logging
import re
import stat
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from conformance.client import (
    FIREFOX_DESKTOP_CLIENT_ID,
    OLDSYNC_SCOPE,
    AuthClient,
    ClientError,
    SyncStorageClient,
    TokenserverClient,
    derive_token_credentials,
    hawk_header,
    pkce_pair,
    sync_key_id,
)
from conftest import EMAIL, PASSWORD, PUBLIC_URL
from fxa_lite import middleware, throttle, tracing
from fxa_lite.app import create_app
from fxa_lite.config import from_dict
from fxa_lite.db import open_database
from fxa_lite.oauth import keys as signing_key_module
from fxa_lite.syncstorage.models import LIMITS

SOURCE = Path(__file__).resolve().parent.parent / "src" / "fxa_lite"


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC_URL)


@pytest.fixture
async def storage(
    bearer_client: AuthClient, tokenserver: TokenserverClient, http, tokenserver_secret: str
) -> SyncStorageClient:
    """A signed-in account with a storage credential, as `test_syncstorage` builds it."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    token = await tokenserver.token(
        grant.access_token, sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])
    )
    return SyncStorageClient(http, token, secret=tokenserver_secret)


@pytest.fixture
async def default_http(db, signing_keys) -> AsyncIterator[httpx.AsyncClient]:
    """The app as an operator gets it: `[security]` left out of the config.

    Everything else in the suite runs with `open_registration` on, because the
    conformance client signs up over HTTP. This fixture is the shipped default.
    """
    app = create_app(from_dict({"public_url": PUBLIC_URL}), db=db, signing_keys=signing_keys)
    async with _client(app) as http:
        yield http


# ==========================================================================
# F1 — request bodies are capped before anything reads them.
# ==========================================================================


async def test_an_oversized_body_never_reaches_a_route(http: httpx.AsyncClient) -> None:
    """413 and errno 113, not the 400 the schema would have produced.

    The body below is not valid JSON for `/account/login`, so a 400 would mean
    pydantic had already parsed it — that is, that the megabyte was buffered.
    """
    response = await http.post(
        "/v1/account/login",
        content=b"x" * (middleware.DEFAULT_MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["errno"] == 113


async def test_a_body_within_the_cap_is_handled_normally(http: httpx.AsyncClient) -> None:
    """The cap is a cap, not a new failure mode: 64 KiB of junk is still a 400."""
    response = await http.post(
        "/v1/account/login",
        content=b'{"email": "' + b"a" * 1024 + b'@example.com", "authPW": "00"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


async def test_the_storage_tier_keeps_its_advertised_limit(http: httpx.AsyncClient) -> None:
    """`/info/configuration` promises `max_request_bytes`; the cap has to match it.

    A body larger than the default cap but smaller than the storage limit must
    reach the storage tier — where it fails authentication, because it is
    unsigned. Answering 413 to a legal Sync batch would stall a client that
    believed what we advertised.
    """
    oversized = await http.post(
        "/storage/1.5/1/storage/history",
        content=b"x" * (LIMITS.max_request_bytes + 1),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    # Sync's whole error vocabulary is one integer, even from a middleware.
    assert oversized.json() == 17

    allowed = await http.post(
        "/storage/1.5/1/storage/history",
        content=b"x" * (middleware.DEFAULT_MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert allowed.status_code == 401


async def test_the_refusal_speaks_the_envelope_of_the_path_it_refused(
    http: httpx.AsyncClient,
) -> None:
    """Three tiers, three shapes — and a middleware runs outside every handler."""
    body = b"x" * (middleware.DEFAULT_MAX_BODY_BYTES + 1)
    headers = {"content-type": "application/json"}

    accounts = await http.post("/v1/account/login", content=body, headers=headers)
    assert set(accounts.json()) >= {"code", "errno", "error", "message"}

    tokenserver = await http.post("/token/1.0/sync/1.5", content=body, headers=headers)
    assert tokenserver.status_code == 413
    assert tokenserver.json()["errors"][0]["description"] == "Request body too large"

    storage = await http.post(
        "/storage/1.5/1/storage/history",
        content=b"x" * (LIMITS.max_request_bytes + 1),
        headers=headers,
    )
    assert storage.status_code == 413
    assert storage.json() == 17
    assert "x-weave-timestamp" in storage.headers


async def test_an_undeclared_body_is_counted_as_it_arrives(http: httpx.AsyncClient) -> None:
    """No `Content-Length` to check, so the chunks are counted instead.

    This is the path that matters: a client that declares its size cannot
    exceed it — the HTTP parser will not deliver more — but a chunked body
    declares nothing at all.
    """

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(9):
            yield b"x" * 8192

    response = await http.post(
        "/v1/account/login", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["errno"] == 113


async def test_a_chunked_body_within_the_cap_still_reaches_its_route(
    http: httpx.AsyncClient,
) -> None:
    """And the buffered body is handed on intact, not swallowed by the counter."""

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"email": "nobody@example.com",'
        yield b' "authPW": "' + b"0" * 64 + b'"}'

    response = await http.post(
        "/v1/account/login", content=chunks(), headers={"content-type": "application/json"}
    )
    # Parsed, and refused for the reason the *body* gives: no such account.
    assert response.status_code == 400
    assert response.json()["errno"] == 102


# ==========================================================================
# F2 — `/v1/account/create` is not open unless it is turned on.
# ==========================================================================


async def test_registration_is_closed_by_default(default_http: httpx.AsyncClient) -> None:
    client = AuthClient(default_http)
    with pytest.raises(ClientError) as caught:
        await client.sign_up(EMAIL, PASSWORD)
    assert caught.value.status == 403
    assert caught.value.errno == 202


async def test_the_closed_answer_carries_no_backoff(default_http: httpx.AsyncClient) -> None:
    """`retryAfter` would stall every FxA request Firefox makes — see `errors.py`."""
    response = await default_http.post(
        "/v1/account/create", json={"email": EMAIL, "authPW": "00" * 32}
    )
    assert "retryAfter" not in response.json()
    assert "retry-after" not in response.headers


async def test_registration_can_be_opened(http: httpx.AsyncClient) -> None:
    """The suite's own fixture sets it, so this is the switch working."""
    account = await AuthClient(http).sign_up(EMAIL, PASSWORD)
    assert account["uid"]


async def test_the_cli_provisions_regardless(db) -> None:
    """`fxa-lite account add` is the signup funnel, and it is not a route."""
    from fxa_lite import accounts

    account = accounts.provision_with_password(db, email=EMAIL, password=PASSWORD)
    assert db.account_by_email(EMAIL).uid == account.uid


# ==========================================================================
# F3 — a failed-password throttle in front of scrypt.
# ==========================================================================


def test_failures_accumulate_and_expire() -> None:
    counter = throttle.FailureThrottle(limit=3, window=60)
    for tick in range(3):
        assert counter.retry_after("a@example.com", now=tick) == 0
        counter.record_failure("a@example.com", now=tick)
    assert counter.retry_after("a@example.com", now=3) > 0
    # The oldest failure was at t=0, so at t=61 it is out of the window.
    assert counter.retry_after("a@example.com", now=61) == 0


def test_a_correct_password_clears_the_history() -> None:
    """The property that makes this safe: an attacker cannot lock anyone out."""
    counter = throttle.FailureThrottle(limit=2, window=60)
    counter.record_failure("a@example.com", now=0)
    counter.record_failure("a@example.com", now=1)
    assert counter.retry_after("a@example.com", now=2) > 0
    counter.record_success("a@example.com")
    assert counter.retry_after("a@example.com", now=2) == 0


def test_accounts_are_counted_separately() -> None:
    counter = throttle.FailureThrottle(limit=1, window=60)
    counter.record_failure("a@example.com", now=0)
    assert counter.retry_after("a@example.com", now=0) > 0
    assert counter.retry_after("b@example.com", now=0) == 0


def test_a_limit_of_zero_disables_it() -> None:
    counter = throttle.FailureThrottle(limit=0, window=60)
    for tick in range(50):
        counter.record_failure("a@example.com", now=tick)
    assert counter.retry_after("a@example.com", now=50) == 0


def test_the_table_cannot_grow_without_bound() -> None:
    counter = throttle.FailureThrottle(limit=1, window=60)
    for index in range(throttle.MAX_ENTRIES + 100):
        counter.record_failure(f"{index}@example.com", now=0)
    assert len(counter._failures) <= throttle.MAX_ENTRIES


@pytest.fixture
def throttled_app(db, signing_keys):
    """Two failures allowed, so the test pays for three scrypts and not eleven."""
    return create_app(
        from_dict(
            {
                "public_url": PUBLIC_URL,
                "security": {"open_registration": True, "failed_login_limit": 2},
            }
        ),
        db=db,
        signing_keys=signing_keys,
    )


@pytest.fixture
async def throttled_http(throttled_app) -> AsyncIterator[httpx.AsyncClient]:
    async with _client(throttled_app) as http:
        yield http


async def test_repeated_wrong_passwords_stop_costing_scrypt(
    throttled_http: httpx.AsyncClient,
) -> None:
    client = AuthClient(throttled_http)
    await client.sign_up(EMAIL, PASSWORD)
    for _ in range(2):
        with pytest.raises(ClientError) as wrong:
            await client.sign_in(EMAIL, "not the password")
        assert wrong.value.errno == 103

    response = await throttled_http.post(
        "/v1/account/login", json={"email": EMAIL, "authPW": "00" * 32}
    )
    assert response.status_code == 429
    body = response.json()
    assert body["errno"] == 114
    # Both halves: Firefox reads the header, and `FxAccountsClient` the field.
    assert body["retryAfter"] > 0
    assert int(response.headers["retry-after"]) > 0


async def test_the_throttle_does_not_lock_out_the_account_owner(
    throttled_http: httpx.AsyncClient,
) -> None:
    client = AuthClient(throttled_http)
    await client.sign_up(EMAIL, PASSWORD)
    with pytest.raises(ClientError):
        await client.sign_in(EMAIL, "not the password")
    signed_in = await client.sign_in(EMAIL, PASSWORD)
    assert signed_in["sessionToken"]


async def test_an_unknown_address_is_never_throttled(
    throttled_http: httpx.AsyncClient, throttled_app
) -> None:
    """It never reaches scrypt either, which is why it is not worth counting.

    `accounts.authenticate` raises before stretching, so an unknown address
    costs one indexed SELECT — and leaves no entry behind, which is what keeps
    the table bounded by the number of real accounts.
    """
    for _ in range(5):
        response = await throttled_http.post(
            "/v1/account/login", json={"email": "nobody@example.com", "authPW": "00" * 32}
        )
        assert response.status_code == 400
        assert response.json()["errno"] == 102
    assert throttled_app.state.throttle._failures == {}


# ==========================================================================
# F4 — the tokenserver's own answer is a credential.
# ==========================================================================


@pytest.fixture
def traced(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger=tracing.LOGGER_NAME)
    return caplog


async def test_a_traced_sync_token_is_not_a_spendable_credential(
    bearer_client: AuthClient,
    tokenserver: TokenserverClient,
    traced: pytest.LogCaptureFixture,
) -> None:
    """`{"id": ..., "key": ...}` is the whole Sync credential, in one response."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    grant = await bearer_client.sync_sign_in(EMAIL, PASSWORD)
    token = await tokenserver.token(
        grant.access_token, sync_key_id(grant.recovered_keys[OLDSYNC_SCOPE])
    )
    written = "\n".join(record.getMessage() for record in traced.records)
    assert "/token/1.0/sync/1.5" in written
    assert token["id"] not in written
    assert token["key"] not in written


def test_id_is_redacted_only_where_it_is_a_credential() -> None:
    """A BSO id, a device id and a client id all have to stay readable."""
    body = json.dumps({"id": "an-identifier-long-enough-to-elide"}).encode()
    assert "…" in tracing.render_body(body, tracing.secrets_for("/token/1.0/sync/1.5"))
    assert "an-identifier" in tracing.render_body(
        body, tracing.secrets_for("/storage/1.5/1/storage/bookmarks")
    )


def test_the_push_keys_are_redacted() -> None:
    body = json.dumps(
        {"pushAuthKey": "A" * 32, "pushPublicKey": "B" * 88, "name": "laptop"}
    ).encode()
    rendered = tracing.render_body(body)
    assert "A" * 32 not in rendered
    assert "B" * 88 not in rendered
    assert "laptop" in rendered


# ==========================================================================
# F5 — what is on the disk, and who can read it.
# ==========================================================================


def test_the_database_is_created_owner_readable(tmp_path: Path) -> None:
    """It holds kA in the clear and session ids that *are* the credential."""
    path = tmp_path / "fxa.sqlite"
    database = open_database(path)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        # WAL and shm inherit the database file's mode, which is why the chmod
        # happens before `PRAGMA journal_mode`.
        for sidecar in (tmp_path / "fxa.sqlite-wal", tmp_path / "fxa.sqlite-shm"):
            if sidecar.exists():
                assert not stat.S_IMODE(sidecar.stat().st_mode) & 0o077
    finally:
        database.close()


def test_an_existing_database_is_narrowed(tmp_path: Path) -> None:
    path = tmp_path / "fxa.sqlite"
    open_database(path).close()
    path.chmod(0o644)
    database = open_database(path)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        database.close()


def test_a_readable_signing_key_is_reported(
    tmp_path: Path, signing_keys, caplog: pytest.LogCaptureFixture
) -> None:
    """Not narrowed — the key may be a mount or an injected secret — but said."""
    from fxa_lite.crypto import jose

    path = tmp_path / "signing-key.json"
    path.write_text(json.dumps(jose.private_key_to_jwk(signing_keys.private)))
    path.chmod(0o644)
    caplog.set_level(logging.WARNING, logger=signing_key_module.logger.name)
    signing_key_module.load(path)
    assert any("chmod 600" in record.getMessage() for record in caplog.records)

    caplog.clear()
    path.chmod(0o600)
    signing_key_module.load(path)
    assert not caplog.records


def test_keygen_writes_the_key_owner_only(tmp_path: Path) -> None:
    """Pinning what `serve` must never widen."""
    from fxa_lite.cli import write_private_jwk

    path = tmp_path / "signing-key.json"
    write_private_jwk(path, {"kid": "x"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ==========================================================================
# F6 — security headers everywhere, not only on the shell.
# ==========================================================================


async def test_every_response_carries_nosniff_and_a_null_policy(
    http: httpx.AsyncClient,
) -> None:
    for path in ("/__version__", "/.well-known/fxa-client-configuration", "/v1/jwks"):
        response = await http.get(path)
        assert response.headers["x-content-type-options"] == "nosniff", path
        assert response.headers["content-security-policy"] == (
            middleware.API_CONTENT_SECURITY_POLICY
        ), path


async def test_an_error_response_carries_them_too(http: httpx.AsyncClient) -> None:
    response = await http.get("/v1/no-such-endpoint")
    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_the_asset_route_is_protected_like_the_shell(http: httpx.AsyncClient) -> None:
    """`icon.svg` is same-origin SVG: a document, if it is navigated to."""
    response = await http.get("/static/icon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["content-security-policy"]


async def test_the_shell_keeps_its_own_policy(http: httpx.AsyncClient) -> None:
    """The middleware fills gaps; it does not overwrite a considered answer."""
    response = await http.get("/")
    assert "script-src 'self'" in response.headers["content-security-policy"]


# ==========================================================================
# F7 — the profile server does not reflect parser detail.
# ==========================================================================


async def test_a_rejected_token_reveals_nothing_about_itself(
    http: httpx.AsyncClient,
) -> None:
    marker = "AAAAAAAAAAAAAAAAAAAAAAAA"
    header = json.dumps({"alg": marker, "kid": marker})
    token = f"{header.encode().hex()}.x.y"
    response = await http.get(
        "/profile/v1/profile", headers={"authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.json()["reason"] == "Invalid token"
    assert marker not in response.text


# ==========================================================================
# Confirm and pin: properties the audit found true and nothing states.
# ==========================================================================


async def test_hawk_grants_no_more_than_bearer(http: httpx.AsyncClient) -> None:
    """`_hawk_id` accepts any 64-hex id; the token *tables* are what separate them.

    A key fetch token and a session token are derived from different HKDF info
    strings and stored in different tables, so presenting one where the other
    belongs finds nothing — under either scheme.
    """
    client = AuthClient(http)
    account = await client.sign_up(EMAIL, PASSWORD, keys=True)
    session, key_fetch = account["sessionToken"], account["keyFetchToken"]

    for token, kind, path in (
        (key_fetch, "keyFetchToken", "/v1/account/profile"),
        (session, "sessionToken", "/v1/account/keys"),
    ):
        # The id is real and correctly derived; it is simply the wrong kind.
        hawk = await http.get(path, headers=hawk_header(token, kind))
        assert hawk.status_code == 401, path
        assert hawk.json()["errno"] == 110

    # And a HAWK header whose id is a *session* id cannot reach a key fetch
    # route by being spelled as one, either: the ids differ.
    assert (
        derive_token_credentials(session, "sessionToken").id
        != derive_token_credentials(session, "keyFetchToken").id
    )


async def test_a_dropped_scope_cannot_be_regranted_on_refresh(
    bearer_client: AuthClient,
) -> None:
    """`strictScopeValidation` drops at authorization; refresh must not restore it."""
    await bearer_client.sign_up(EMAIL, PASSWORD)
    verifier, challenge = pkce_pair()
    unregistered = "https://example.com/apps/whatever"
    account = await bearer_client.sign_in(EMAIL, PASSWORD)
    authorization = await bearer_client.oauth_authorization(
        account["sessionToken"],
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        state="s",
        scope=f"profile {unregistered}",
        access_type="offline",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert unregistered not in authorization["scope"]

    token = await bearer_client.oauth_token(
        client_id=FIREFOX_DESKTOP_CLIENT_ID,
        grant_type="authorization_code",
        code=authorization["code"],
        code_verifier=verifier,
    )
    assert unregistered not in token["scope"]

    with pytest.raises(ClientError) as caught:
        await bearer_client.oauth_token(
            client_id=FIREFOX_DESKTOP_CLIENT_ID,
            grant_type="refresh_token",
            refresh_token=token["refresh_token"],
            scope=unregistered,
        )
    # An error, not a grant: the dropped scope is outside every allow-list.
    assert caught.value.errno == 114


def test_one_place_mints_the_tokenserver_audience() -> None:
    """The tokenserver's `aud` check is stricter than upstream's, and rests on this."""
    minters = [
        path
        for path in SOURCE.rglob("*.py")
        if re.search(r'"aud"\s*:', path.read_text())
    ]
    assert [path.name for path in minters] == ["grant.py"]


async def test_a_bso_id_full_of_sql_is_data(storage: SyncStorageClient) -> None:
    """`BSO_ID_RE` admits any printable ASCII, quotes and comment markers included.

    Every f-string in `store.py` interpolates a literal — a run of `?`, a fixed
    column list, an `ORDER BY` chosen by dict lookup — and the values are bound.
    An id like this one is therefore a perfectly ordinary record.
    """
    # No character here percent-encodes, so the signed path and the routed one
    # are the same string — the interop edge `AUDIT.md` notes under "not fixed".
    hostile = "'or'1'='1"
    written = await storage.put(
        f"/storage/bookmarks/{hostile}", json_body={"payload": "kept"}
    )
    assert written.status_code == 200

    listed = await storage.get("/storage/bookmarks", params={"full": "1"})
    assert [record["id"] for record in listed.json()] == [hostile]
    # The table is still there, which is the whole point.
    collections = await storage.get("/info/collections")
    assert "bookmarks" in collections.json()


async def test_a_hostile_sort_parameter_never_reaches_sql(
    storage: SyncStorageClient,
) -> None:
    """`query.sort` reaches SQL only as a key into a table of literals."""
    response = await storage.get(
        "/storage/bookmarks", params={"sort": "index; DROP TABLE sync_bso"}
    )
    assert response.status_code == 400


async def test_no_envelope_carries_a_traceback(http: httpx.AsyncClient, app) -> None:
    """The bare-`Exception` handler answers with a fixed message, and nothing else."""

    @app.get("/boom", include_in_schema=False)
    def boom() -> dict[str, str]:
        raise RuntimeError("a filesystem path and a SQL fragment walk into a bar")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["errno"] == 999
    assert body["message"] == "Unspecified error"
    assert "walk into a bar" not in response.text
    assert "Traceback" not in response.text


def test_every_secret_comparison_is_constant_time() -> None:
    """A `==` on a secret is a timing oracle; `hmac.compare_digest` is not.

    Read as a source pin rather than a behavioural one because the difference
    is invisible from outside: the wrong answer is still the right answer, just
    a few nanoseconds sooner.
    """
    users = sorted(
        path.relative_to(SOURCE).as_posix()
        for path in SOURCE.rglob("*.py")
        if "compare_digest" in path.read_text()
    )
    assert users == [
        "crypto/onepw.py",
        "crypto/tokens.py",
        "oauth/routes.py",
        "syncstorage/credentials.py",
        "syncstorage/hawk.py",
    ]
