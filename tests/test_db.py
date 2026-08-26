# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Storage behaviours the API depends on but does not exercise directly."""

from __future__ import annotations

import sqlite3

import pytest

from fxa_lite import accounts
from fxa_lite.db import MIGRATIONS, SCHEMA_VERSION, Database, DatabaseError, open_database

PASSWORD = "correct horse battery staple"


def test_migrate_is_idempotent(tmp_path) -> None:
    path = tmp_path / "fxa.sqlite"
    open_database(path).close()
    database = open_database(path)
    try:
        assert database.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        database.close()


def test_an_older_database_is_migrated_in_place(tmp_path) -> None:
    """Someone already running fxa-lite must not have to start over.

    The database is built at version 1 by hand — the state a phase 4 install is
    in — and then opened normally, which should add only what is missing.
    """
    path = tmp_path / "fxa.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(MIGRATIONS[0])
    connection.execute("PRAGMA user_version = 1")
    connection.commit()
    connection.close()

    database = open_database(path)
    try:
        assert database.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert database.sync_users("nobody") == []
    finally:
        database.close()


def test_a_phase_5_database_gains_the_storage_tables(tmp_path) -> None:
    """The upgrade an installation running the tokenserver but not storage sees."""
    path = tmp_path / "fxa.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(MIGRATIONS[0])
    connection.executescript(MIGRATIONS[1])
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    connection.close()

    database = open_database(path)
    try:
        assert database.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert database.connection.execute("SELECT COUNT(*) FROM sync_bso").fetchone()[0] == 0
        # Collection id 0 is reserved for the tombstone and seeded by the
        # migration; without it, deleting a collection has nothing to record
        # the storage timestamp against.
        assert database.connection.execute(
            "SELECT name FROM sync_collections WHERE id = 0"
        ).fetchone()[0] == ""
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


def _account(database: Database, email: str):
    return accounts.provision_with_password(database, email=email, password=PASSWORD)


def test_sync_uids_are_never_reused(tmp_path) -> None:
    """A recycled uid would hand a new user the previous one's collections.

    SQLite reuses the largest rowid after a delete unless the column is
    AUTOINCREMENT, and the Sync uid *is* the storage directory — so this is the
    property the column declaration exists for.
    """
    database = open_database(tmp_path / "fxa.sqlite")
    try:
        account = _account(database, "recycler@example.com")
        first = database.create_sync_user(
            fxa_uid=account.uid,
            client_state="00" * 16,
            generation=1,
            keys_changed_at=1,
            created_at=1,
        )
        database.connection.execute("DELETE FROM sync_users WHERE uid = ?", (first.uid,))
        second = database.create_sync_user(
            fxa_uid=account.uid,
            client_state="11" * 16,
            generation=2,
            keys_changed_at=2,
            created_at=2,
        )
        assert second.uid > first.uid
    finally:
        database.close()


def test_sync_users_come_back_newest_first(tmp_path) -> None:
    """"Newest" is greatest generation, then most recently created — the
    tokenserver's own definition of which row is the live one."""
    database = open_database(tmp_path / "fxa.sqlite")
    try:
        account = _account(database, "rotator@example.com")
        for generation in (3, 1, 2):
            database.create_sync_user(
                fxa_uid=account.uid,
                client_state=f"{generation:032x}",
                generation=generation,
                keys_changed_at=generation,
                created_at=generation,
            )
        assert [user.generation for user in database.sync_users(account.uid)] == [3, 2, 1]
    finally:
        database.close()


def test_deleting_an_account_takes_its_sync_users_with_it(tmp_path) -> None:
    """Upstream cannot cascade here — its tokenserver is a separate database."""
    database = open_database(tmp_path / "fxa.sqlite")
    try:
        account = _account(database, "departing@example.com")
        database.create_sync_user(
            fxa_uid=account.uid,
            client_state="00" * 16,
            generation=1,
            keys_changed_at=1,
            created_at=1,
        )
        database.delete_account(account.uid)
        assert database.sync_users(account.uid) == []
    finally:
        database.close()


def test_replacing_leaves_exactly_one_live_row(tmp_path) -> None:
    database = open_database(tmp_path / "fxa.sqlite")
    try:
        account = _account(database, "keys-rotated@example.com")
        old = database.create_sync_user(
            fxa_uid=account.uid,
            client_state="00" * 16,
            generation=1,
            keys_changed_at=1,
            created_at=1,
        )
        new = database.create_sync_user(
            fxa_uid=account.uid,
            client_state="11" * 16,
            generation=2,
            keys_changed_at=2,
            created_at=2,
        )
        assert database.replace_other_sync_users(account.uid, keep=new.uid, replaced_at=9) == 1
        users = {user.uid: user for user in database.sync_users(account.uid)}
        assert users[old.uid].replaced_at == 9
        assert users[new.uid].replaced_at is None
        # Idempotent: a second pass must not restamp a row that is already retired.
        assert database.replace_other_sync_users(account.uid, keep=new.uid, replaced_at=99) == 0
    finally:
        database.close()

