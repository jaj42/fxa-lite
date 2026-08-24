"""Storage behaviours the API depends on but does not exercise directly."""

from __future__ import annotations

import sqlite3

import pytest

from fxa_lite import accounts
from fxa_lite.db import SCHEMA_VERSION, Database, DatabaseError, open_database

PASSWORD = "correct horse battery staple"


def test_migrate_is_idempotent(tmp_path) -> None:
    path = tmp_path / "fxa.sqlite"
    open_database(path).close()
    database = open_database(path)
    try:
        assert database.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        database.close()


def test_a_newer_schema_is_refused(tmp_path) -> None:
    """Better to stop than to run half-understood queries against someone's keys."""
    path = tmp_path / "fxa.sqlite"
    open_database(path).close()
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    connection.close()

    with pytest.raises(DatabaseError, match="newer fxa-lite"):
        open_database(path)


def test_wal_is_enabled(tmp_path) -> None:
    database = open_database(tmp_path / "fxa.sqlite")
    try:
        mode = database.connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        database.close()


def test_deleting_an_account_cascades(db: Database) -> None:
    account = accounts.provision_with_password(db, email="a@example.com", password=PASSWORD)
    _, session = accounts.start_session(db, account)
    _, stretched = accounts.authenticate(
        db,
        email="a@example.com",
        auth_pw=_auth_pw("a@example.com"),
    )
    key_fetch = accounts.start_key_fetch(db, account, stretched)

    db.delete_account(account.uid)
    assert db.session_token(session.token_id) is None
    assert db.key_fetch_token(key_fetch.id.hex()) is None


def test_transactions_roll_back(db: Database) -> None:
    account = accounts.provision_with_password(db, email="a@example.com", password=PASSWORD)
    with pytest.raises(RuntimeError), db.transaction() as connection:
        connection.execute("DELETE FROM accounts WHERE uid = ?", (account.uid,))
        raise RuntimeError("boom")
    assert db.account(account.uid) is not None


def test_email_lookup_is_case_insensitive(db: Database) -> None:
    account = accounts.provision_with_password(db, email="Bob@Example.COM", password=PASSWORD)
    # The stored spelling is preserved — v1 stretching salts with it — while the
    # lookup key is folded.
    assert account.email == "Bob@Example.COM"
    found = db.account_by_email("bob@example.com")
    assert found is not None and found.uid == account.uid


def _auth_pw(email: str) -> bytes:
    from fxa_lite.crypto import onepw

    return onepw.credentials_v1(email, PASSWORD).auth_pw
