"""`fxa-lite sync inspect` — what is on the server, for the operator.

Every household report this project has had ("desktop bookmarks are not
arriving", "tabs are not syncing") turned out to be answerable from three
facts, none of which appears in a log: how many Sync uids the account has, what
each collection holds, and whether both devices are present. This command is
those three facts, and these tests are the shapes that answer them.
"""

from __future__ import annotations

import time

import pytest

from fxa_lite.cli import main
from fxa_lite.db import open_database
from fxa_lite.syncstorage.store import SyncStore, quantize

PASSWORD = "correct horse battery staple"


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "fxa.toml"
    path.write_text(
        'public_url = "http://localhost:9000"\n'
        "[paths]\n"
        'database = "fxa.sqlite"\n'
        'signing_key = "signing-key.json"\n'
    )
    return path


def _account(config_file, email: str = "bob@example.com") -> str:
    assert main(["account", "add", "-c", str(config_file), email, "--password", PASSWORD]) == 0
    db = open_database(config_file.parent / "fxa.sqlite")
    try:
        account = db.account_by_email(email)
        assert account is not None
        return account.uid
    finally:
        db.close()


def _sync_user(config_file, fxa_uid: str, *, client_state: str) -> int:
    db = open_database(config_file.parent / "fxa.sqlite")
    try:
        now = int(time.time() * 1000)
        user = db.create_sync_user(
            fxa_uid=fxa_uid,
            client_state=client_state,
            generation=now,
            keys_changed_at=now,
            created_at=now,
        )
        return user.uid
    finally:
        db.close()


def _write(config_file, uid: int, collection: str, *bso_ids: str) -> None:
    """One call, one timestamp — which is also the protocol.

    A second write into the same collection inside the same hundredth of a
    second is refused (`check_write`), so a test that wants two records writes
    them together rather than racing its own clock.
    """
    db = open_database(config_file.parent / "fxa.sqlite")
    try:
        store = SyncStore(db, uid, quantize(int(time.time() * 1000)))
        with store.transaction():
            store.post_bsos(collection, [_Posted(bso_id) for bso_id in bso_ids])
    finally:
        db.close()


class _Posted:
    """The three attributes `post_bsos` reads off a record."""

    def __init__(self, bso_id: str) -> None:
        self.id = bso_id
        self.payload = "{}"
        self.sortindex = None
        self.ttl = None


def test_an_account_that_has_never_synced_says_so(config_file, capsys) -> None:
    _account(config_file)
    assert main(["sync", "inspect", "-c", str(config_file)]) == 0
    assert "never synced" in capsys.readouterr().out


def test_no_accounts_at_all(config_file, capsys) -> None:
    assert main(["sync", "inspect", "-c", str(config_file)]) == 0
    assert "no accounts" in capsys.readouterr().out


def test_it_reports_the_uid_and_every_collection(config_file, capsys) -> None:
    fxa_uid = _account(config_file)
    uid = _sync_user(config_file, fxa_uid, client_state="a" * 32)
    _write(config_file, uid, "bookmarks", "menu")
    _write(config_file, uid, "tabs", "device-one", "device-two")

    assert main(["sync", "inspect", "-c", str(config_file)]) == 0
    out = capsys.readouterr().out
    assert f"sync uid {uid}" in out
    assert "(live)" in out
    assert "bookmarks" in out
    # Two devices syncing tabs are two records; that count is the whole point.
    assert "2 record(s)" in out
    assert "one per device" in out


def test_a_retired_uid_is_shown_beside_the_live_one(config_file, capsys) -> None:
    """A key rotation leaves the old records where they are, unreadable.

    They are not deleted and they still take disk, so an operator asking "where
    did my history go" needs to see both rows rather than only the empty one
    the browser is now using.
    """
    fxa_uid = _account(config_file)
    old = _sync_user(config_file, fxa_uid, client_state="a" * 32)
    _write(config_file, old, "history", "one")

    db = open_database(config_file.parent / "fxa.sqlite")
    try:
        db.replace_sync_user(old, int(time.time() * 1000))
    finally:
        db.close()
    new = _sync_user(config_file, fxa_uid, client_state="b" * 32)

    assert main(["sync", "inspect", "-c", str(config_file)]) == 0
    out = capsys.readouterr().out
    assert f"sync uid {old}" in out and "replaced" in out
    assert f"sync uid {new}" in out and "(live)" in out
    assert "no collections" in out
