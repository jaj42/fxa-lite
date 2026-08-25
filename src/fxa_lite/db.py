"""SQLite storage: connection handling, schema, and the account/token queries.

One file, WAL mode, `sqlite3` from the stdlib.  The reference stack splits this
across MySQL (accounts, tokens), Redis (sessions, devices) and Firestore; for a
handful of accounts a single database is not a compromise, it is the point.

Two conventions carried over from upstream, because they leak onto the wire:
timestamps are **integer milliseconds** since the epoch, and every key, token id
and uid is stored as a **lowercase hex string** rather than a blob — that is the
form the API speaks, and hex round-trips through `sqlite3` without adapters.

Connections are per-thread: FastAPI runs `def` routes in a worker pool, and a
`sqlite3.Connection` may not cross threads.  WAL lets those threads read while
one writes.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MEMORY = Path(":memory:")

logger = logging.getLogger(__name__)

SCHEMA_V1 = """
CREATE TABLE accounts (
    uid                TEXT    PRIMARY KEY,
    email              TEXT    NOT NULL,
    -- Lowercased email; the uniqueness constraint and every lookup use it, so
    -- that Bob@example.com and bob@example.com cannot both be registered.
    normalized_email   TEXT    NOT NULL UNIQUE,
    email_code         TEXT    NOT NULL,
    -- kA: never leaves the server except inside a keyFetchToken bundle.
    ka                 TEXT    NOT NULL,
    -- wrapKb XOR the password-derived wrapper; useless without the password.
    wrap_wrap_kb       TEXT    NOT NULL,
    auth_salt          TEXT    NOT NULL,
    verify_hash        TEXT    NOT NULL,
    verifier_version   INTEGER NOT NULL,
    verifier_set_at    INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    -- Milliseconds of the last key rotation; half of every Sync `kid`.
    keys_changed_at    INTEGER NOT NULL,
    profile_changed_at INTEGER NOT NULL,
    locale             TEXT
) STRICT;

CREATE TABLE session_tokens (
    token_id         TEXT    PRIMARY KEY,
    uid              TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    -- The HAWK MAC key. Stored because the protocol says so; neither we nor the
    -- reference server verifies a MAC with it.
    auth_key         TEXT    NOT NULL,
    created_at       INTEGER NOT NULL,
    -- When the password was last checked; becomes `authAt` / the JWT `auth_time`.
    auth_at          INTEGER NOT NULL,
    last_access_time INTEGER NOT NULL,
    user_agent       TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX session_tokens_uid ON session_tokens(uid);

CREATE TABLE key_fetch_tokens (
    token_id   TEXT    PRIMARY KEY,
    uid        TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    auth_key   TEXT    NOT NULL,
    -- kA || wrapKb, bundled at creation time under the token's bundleKey. The
    -- token is single-use, so this row is deleted the moment it is read.
    key_bundle TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX key_fetch_tokens_uid ON key_fetch_tokens(uid);

CREATE TABLE devices (
    id                    TEXT    PRIMARY KEY,
    uid                   TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    -- A device is owned either by a session token (Desktop) or, later, by an
    -- OAuth refresh token (mobile). Deleting the session deletes the device.
    session_token_id      TEXT    REFERENCES session_tokens(token_id) ON DELETE CASCADE,
    refresh_token_id      TEXT,
    name                  TEXT    NOT NULL DEFAULT '',
    type                  TEXT    NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    push_callback         TEXT    NOT NULL DEFAULT '',
    push_public_key       TEXT    NOT NULL DEFAULT '',
    push_auth_key         TEXT    NOT NULL DEFAULT '',
    push_endpoint_expired INTEGER NOT NULL DEFAULT 0,
    available_commands    TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX devices_uid ON devices(uid);
CREATE UNIQUE INDEX devices_session_token_id
    ON devices(session_token_id) WHERE session_token_id IS NOT NULL;

-- Phase 3 tables. Created here so there is one schema version, not two.
CREATE TABLE oauth_codes (
    code                  TEXT    PRIMARY KEY,
    uid                   TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    client_id             TEXT    NOT NULL,
    scope                 TEXT    NOT NULL,
    created_at            INTEGER NOT NULL,
    auth_at               INTEGER NOT NULL,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    -- The scoped-key bundle, encrypted to the client's public JWK. We never
    -- decrypt it; we hand it back at token time.
    keys_jwe              TEXT,
    session_token_id      TEXT,
    offline               INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE refresh_tokens (
    token_id     TEXT    PRIMARY KEY,
    uid          TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    client_id    TEXT    NOT NULL,
    scope        TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
) STRICT;

CREATE INDEX refresh_tokens_uid ON refresh_tokens(uid);
"""

SCHEMA_V2 = """
-- Phase 5: the Sync tokenserver's user table.
--
-- Sync identifies an account by a small integer, not by the FxA uid, and that
-- integer is the directory its storage lives in.  A client-state change (the
-- user's keys rotated) does not update the row: it *replaces* it, so the new
-- key material gets a new uid and cannot read records encrypted under the old
-- one.  The old row stays behind, both as the record of a client state that
-- must never be accepted again and as the handle for deleting its storage.
--
-- AUTOINCREMENT, not a bare rowid: SQLite reuses the largest rowid after a
-- delete, and a recycled uid would hand a new user the previous one's
-- collections.
--
-- Upstream keys this table on `<fxa_uid>@<email domain>` because its
-- tokenserver is a separate deployment that has never seen the accounts table.
-- Ours is the same file, so the foreign key is real and deleting an account
-- takes its Sync data with it.
CREATE TABLE sync_users (
    uid             INTEGER PRIMARY KEY AUTOINCREMENT,
    fxa_uid         TEXT    NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    -- sha256(kB)[:16] as hex: the fingerprint of the key the client is using.
    client_state    TEXT    NOT NULL,
    generation      INTEGER NOT NULL,
    keys_changed_at INTEGER,
    created_at      INTEGER NOT NULL,
    -- Set when a newer row supersedes this one; NULL for the row in use.
    replaced_at     INTEGER
) STRICT;

CREATE INDEX sync_users_fxa_uid ON sync_users(fxa_uid);
"""

SCHEMA_V3 = """
-- Phase 6: Sync 1.5 storage.
--
-- Everything here hangs off `sync_users.uid`, the small integer the tokenserver
-- allocates -- not the FxA uid.  That is deliberate and it is the whole point
-- of the split: rotating the Sync key mints a new `sync_users` row, and the
-- records written under the old key stay attached to the old uid where nothing
-- will try to decrypt them with the new one.
--
-- Upstream (`syncstorage-mysql/src/db/schema.rs`) is four tables with the same
-- shape; the column names differ because theirs still carry Sync 1.1's
-- spelling (`userid`, `collection`, `ttl`).  What is reproduced exactly is the
-- semantics: a per-collection last-modified that a write must move forward,
-- and an expiry stored as an absolute instant rather than a duration.
CREATE TABLE sync_collections (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE
) STRICT;

-- Collection id 0 is the tombstone, and belongs to no collection.  Deleting a
-- collection has to move the *storage* timestamp even though it leaves no
-- collection behind to carry one; upstream records that by writing a
-- `user_collections` row under this reserved id, which then falls out of the
-- MAX() that defines the storage timestamp.  Seeded with the empty name so the
-- foreign key below is real and so no collection can ever claim the id.
INSERT INTO sync_collections (id, name) VALUES (0, '');

CREATE TABLE sync_user_collections (
    uid           INTEGER NOT NULL REFERENCES sync_users(uid) ON DELETE CASCADE,
    collection_id INTEGER NOT NULL REFERENCES sync_collections(id),
    modified      INTEGER NOT NULL,
    PRIMARY KEY (uid, collection_id)
) STRICT;

CREATE TABLE sync_bso (
    uid           INTEGER NOT NULL REFERENCES sync_users(uid) ON DELETE CASCADE,
    collection_id INTEGER NOT NULL REFERENCES sync_collections(id),
    id            TEXT    NOT NULL,
    sortindex     INTEGER,
    payload       TEXT    NOT NULL,
    modified      INTEGER NOT NULL,
    -- Absolute expiry in milliseconds, not a TTL: a row is invisible once it
    -- passes, and is only actually deleted when something happens to touch it.
    expiry        INTEGER NOT NULL,
    PRIMARY KEY (uid, collection_id, id)
) STRICT;

-- The shape of every read: one collection of one user, ordered by modified and
-- filtered on expiry.
CREATE INDEX sync_bso_modified ON sync_bso(uid, collection_id, modified);

-- A batch is an upload in progress: rows accumulate here across several POSTs
-- and land in `sync_bso` all at once, sharing a single timestamp, when the
-- client commits.  The id is a millisecond timestamp, which is also how its
-- lifetime is checked -- see `BATCH_LIFETIME`.
CREATE TABLE sync_batches (
    uid           INTEGER NOT NULL REFERENCES sync_users(uid) ON DELETE CASCADE,
    batch_id      INTEGER NOT NULL,
    collection_id INTEGER NOT NULL REFERENCES sync_collections(id),
    PRIMARY KEY (uid, batch_id)
) STRICT;

CREATE TABLE sync_batch_items (
    uid        INTEGER NOT NULL,
    batch_id   INTEGER NOT NULL,
    id         TEXT    NOT NULL,
    sortindex  INTEGER,
    payload    TEXT,
    -- Kept as the client sent it, in seconds, because the instant it becomes
    -- an expiry is the commit's timestamp and not this row's.
    ttl_offset INTEGER,
    PRIMARY KEY (uid, batch_id, id),
    FOREIGN KEY (uid, batch_id) REFERENCES sync_batches(uid, batch_id) ON DELETE CASCADE
) STRICT;
"""

SCHEMA_V4 = """
-- Phase 8: a device owned by an OAuth refresh token rather than a session token.
--
-- The column has been there since v1; what was missing is the constraint that
-- makes it a *pointer* rather than a note.  Firefox for Android authenticates
-- device registration with its refresh token and sends no device id, so the
-- server has to find the record that token already owns -- exactly as it finds
-- the one a session token owns -- or every reconnect leaves another orphan in
-- the device list.
--
-- Partial, like its session-token sibling: the desktop rows have NULL here and
-- SQLite would otherwise call them all duplicates of each other.
CREATE UNIQUE INDEX devices_refresh_token_id
    ON devices(refresh_token_id) WHERE refresh_token_id IS NOT NULL;
"""

#: Ordered DDL steps. A database stamped `user_version = N` has had the first
#: `N` applied, so an existing file is upgraded by running the rest.
MIGRATIONS = (SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4)

#: Stored in SQLite's `user_version`.
SCHEMA_VERSION = len(MIGRATIONS)


class DatabaseError(RuntimeError):
    """Raised for a database that cannot be opened or is from a future version."""


@dataclass(frozen=True, slots=True)
class Account:
    uid: str
    email: str
    normalized_email: str
    email_code: str
    ka: str
    wrap_wrap_kb: str
    auth_salt: str
    verify_hash: str
    verifier_version: int
    verifier_set_at: int
    created_at: int
    keys_changed_at: int
    profile_changed_at: int
    locale: str | None = None


@dataclass(frozen=True, slots=True)
class SessionToken:
    token_id: str
    uid: str
    auth_key: str
    created_at: int
    auth_at: int
    last_access_time: int
    user_agent: str = ""

    @property
    def last_auth_at(self) -> int:
        """`SessionToken.lastAuthAt()` — seconds, and the JWT's `auth_time`."""
        return (self.auth_at or self.created_at) // 1000


@dataclass(frozen=True, slots=True)
class KeyFetchToken:
    token_id: str
    uid: str
    auth_key: str
    key_bundle: str
    created_at: int


@dataclass(frozen=True, slots=True)
class OauthCode:
    """A single-use authorization code, stored under `sha256(code)`.

    The code itself is never written down: the client holds it, and a database
    leak must not let anyone redeem it. `auth_at` is milliseconds like every
    other timestamp here, even though it leaves as seconds in `auth_at` /
    `auth_time`.
    """

    code: str
    uid: str
    client_id: str
    scope: str
    created_at: int
    auth_at: int
    code_challenge: str | None
    code_challenge_method: str | None
    keys_jwe: str | None
    session_token_id: str | None
    offline: bool


@dataclass(frozen=True, slots=True)
class RefreshToken:
    """A long-lived grant, stored under `sha256(token)` for the same reason."""

    token_id: str
    uid: str
    client_id: str
    scope: str
    created_at: int
    last_used_at: int


@dataclass(frozen=True, slots=True)
class SyncUser:
    """One (account, key generation) pair, and the Sync uid it owns.

    `keys_changed_at` is nullable rather than 0-defaulted because the
    tokenserver protocol distinguishes "this client has never reported one"
    from "it reported zero", and rejects a client that stops reporting one it
    has already sent.
    """

    uid: int
    fxa_uid: str
    client_state: str
    generation: int
    keys_changed_at: int | None
    created_at: int
    replaced_at: int | None


@dataclass(frozen=True, slots=True)
class Device:
    id: str
    uid: str
    session_token_id: str | None
    refresh_token_id: str | None
    name: str
    type: str
    created_at: int
    push_callback: str
    push_public_key: str
    push_auth_key: str
    push_endpoint_expired: bool
    available_commands: dict[str, str] = field(default_factory=dict)


def _restrict(path: Path) -> None:
    """Narrow a database file to owner-only, if it is not already.

    Best effort on purpose: a database on a filesystem with no Unix modes at
    all (a network share, a bind mount with a fixed mode) is a deployment
    choice, and failing to start over it would be worse than the warning.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - the connect above would have failed
        return
    if not mode & 0o077:
        return
    try:
        path.chmod(0o600)
    except OSError:
        logger.warning(
            "%s is mode %o and cannot be narrowed; it holds account key material",
            path,
            mode,
        )


class Database:
    """Owns the connection pool and every statement fxa-lite runs."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._keeper: sqlite3.Connection | None = None
        if self.path == MEMORY:
            # A plain `:memory:` database belongs to the connection that opened
            # it, so per-thread connections would each get their own empty one.
            # Shared cache plus one connection held open for our lifetime gives
            # every thread the same database, and lets tests skip the disk.
            self._dsn = f"file:fxa-lite-{id(self):x}?mode=memory&cache=shared"
            self._uri = True
            self._keeper = self._connect()
        else:
            self._dsn = str(self.path)
            self._uri = False

    # -- connection management ------------------------------------------------

    @property
    def connection(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is None:
            connection = self._connect()
            self._local.connection = connection
        return connection

    def _connect(self) -> sqlite3.Connection:
        if not self._uri:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # `isolation_level=None` turns off the sqlite3 module's implicit
            # transaction handling, so `transaction()` below is the only thing
            # that opens one and its boundaries are visible in the code.
            connection = sqlite3.connect(self._dsn, isolation_level=None, uri=self._uri)
        except sqlite3.Error as exc:  # pragma: no cover - depends on the filesystem
            raise DatabaseError(f"cannot open database {self.path}: {exc}") from exc
        connection.row_factory = sqlite3.Row
        if not self._uri:
            # Before WAL, and before anything is written. `sqlite3.connect`
            # creates the file with the process umask, so a default umask
            # leaves it world-readable — and this file holds kA in the clear,
            # the sealed key bundles, and the session token ids that *are* the
            # credential a client presents (the accounts API authenticates on
            # the id and verifies no MAC). Doing it here rather than after the
            # PRAGMA is what makes SQLite create `-wal` and `-shm` with the
            # same mode: it copies the database file's permissions.
            _restrict(self.path)
            # WAL is a file-format thing; an in-memory database stays in memory.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA foreign_keys = ON")
        # Wait rather than fail when another thread holds the write lock.
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def close(self) -> None:
        """Close this thread's connection. Other threads close theirs on exit."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            self._local.connection = None
        if self._keeper is not None:
            # Closing the last connection to a shared-cache memory database
            # discards it, so this must go last.
            self._keeper.close()
            self._keeper = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")

    def ping(self) -> None:
        """`__heartbeat__`: prove the file is readable, not merely that we started."""
        self.connection.execute("SELECT 1").fetchone()

    # -- schema ---------------------------------------------------------------

    def migrate(self) -> None:
        """Create the schema, or refuse a database we are too old to understand."""
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise DatabaseError(
                f"{self.path} was written by a newer fxa-lite "
                f"(schema {version}, we speak {SCHEMA_VERSION})"
            )
        # `executescript` commits whatever transaction is open before it runs, so
        # the BEGIN/COMMIT have to live inside the script for the DDL and the
        # version stamp to land together. PRAGMA takes no parameter binding.
        for step, ddl in enumerate(MIGRATIONS[version:], start=version + 1):
            self.connection.executescript(
                f"BEGIN IMMEDIATE;\n{ddl}\nPRAGMA user_version = {step};\nCOMMIT;"
            )

    # -- accounts -------------------------------------------------------------

    def create_account(self, account: Account) -> Account:
        try:
            self.connection.execute(
                """
                INSERT INTO accounts (
                    uid, email, normalized_email, email_code, ka, wrap_wrap_kb,
                    auth_salt, verify_hash, verifier_version, verifier_set_at,
                    created_at, keys_changed_at, profile_changed_at, locale
                ) VALUES (
                    :uid, :email, :normalized_email, :email_code, :ka, :wrap_wrap_kb,
                    :auth_salt, :verify_hash, :verifier_version, :verifier_set_at,
                    :created_at, :keys_changed_at, :profile_changed_at, :locale
                )
                """,
                _as_row(account),
            )
        except sqlite3.IntegrityError as exc:
            raise AccountExistsError(account.email) from exc
        return account

    def account(self, uid: str) -> Account | None:
        return _one(
            Account, self.connection.execute("SELECT * FROM accounts WHERE uid = ?", (uid,))
        )

    def account_by_email(self, email: str) -> Account | None:
        return _one(
            Account,
            self.connection.execute(
                "SELECT * FROM accounts WHERE normalized_email = ?", (normalize_email(email),)
            ),
        )

    def accounts(self) -> list[Account]:
        rows = self.connection.execute("SELECT * FROM accounts ORDER BY created_at")
        return [Account(**dict(row)) for row in rows]

    def delete_account(self, uid: str) -> bool:
        # Tokens and devices go with it: every child table cascades on uid.
        cursor = self.connection.execute("DELETE FROM accounts WHERE uid = ?", (uid,))
        return cursor.rowcount > 0

    def touch_profile(self, uid: str, at: int) -> None:
        self.connection.execute(
            "UPDATE accounts SET profile_changed_at = ? WHERE uid = ?", (at, uid)
        )

    # -- session tokens -------------------------------------------------------

    def create_session_token(self, token: SessionToken) -> SessionToken:
        self.connection.execute(
            """
            INSERT INTO session_tokens (
                token_id, uid, auth_key, created_at, auth_at, last_access_time, user_agent
            ) VALUES (
                :token_id, :uid, :auth_key, :created_at, :auth_at, :last_access_time, :user_agent
            )
            """,
            _as_row(token),
        )
        return token

    def session_token(self, token_id: str) -> SessionToken | None:
        return _one(
            SessionToken,
            self.connection.execute(
                "SELECT * FROM session_tokens WHERE token_id = ?", (token_id,)
            ),
        )

    def session_tokens(self, uid: str) -> list[SessionToken]:
        rows = self.connection.execute(
            "SELECT * FROM session_tokens WHERE uid = ? ORDER BY created_at", (uid,)
        )
        return [SessionToken(**dict(row)) for row in rows]

    def touch_session_token(self, token_id: str, at: int) -> None:
        self.connection.execute(
            "UPDATE session_tokens SET last_access_time = ? WHERE token_id = ?", (at, token_id)
        )

    def reauthenticate_session_token(self, token_id: str, at: int) -> None:
        """Record a fresh password check on an existing session (`/session/reauth`)."""
        self.connection.execute(
            "UPDATE session_tokens SET auth_at = ?, last_access_time = ? WHERE token_id = ?",
            (at, at, token_id),
        )

    def delete_session_token(self, token_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM session_tokens WHERE token_id = ?", (token_id,)
        )
        return cursor.rowcount > 0

    # -- key fetch tokens -----------------------------------------------------

    def create_key_fetch_token(self, token: KeyFetchToken) -> KeyFetchToken:
        self.connection.execute(
            """
            INSERT INTO key_fetch_tokens (token_id, uid, auth_key, key_bundle, created_at)
            VALUES (:token_id, :uid, :auth_key, :key_bundle, :created_at)
            """,
            _as_row(token),
        )
        return token

    def key_fetch_token(self, token_id: str) -> KeyFetchToken | None:
        return _one(
            KeyFetchToken,
            self.connection.execute(
                "SELECT * FROM key_fetch_tokens WHERE token_id = ?", (token_id,)
            ),
        )

    def delete_key_fetch_token(self, token_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM key_fetch_tokens WHERE token_id = ?", (token_id,)
        )
        return cursor.rowcount > 0

    # -- oauth codes ----------------------------------------------------------

    def create_oauth_code(self, code: OauthCode) -> OauthCode:
        row = _as_row(code)
        row["offline"] = int(code.offline)
        self.connection.execute(
            """
            INSERT INTO oauth_codes (
                code, uid, client_id, scope, created_at, auth_at, code_challenge,
                code_challenge_method, keys_jwe, session_token_id, offline
            ) VALUES (
                :code, :uid, :client_id, :scope, :created_at, :auth_at, :code_challenge,
                :code_challenge_method, :keys_jwe, :session_token_id, :offline
            )
            """,
            row,
        )
        return code

    def oauth_code(self, code_id: str) -> OauthCode | None:
        row = self.connection.execute(
            "SELECT * FROM oauth_codes WHERE code = ?", (code_id,)
        ).fetchone()
        if row is None:
            return None
        values = dict(row)
        values["offline"] = bool(values["offline"])
        return OauthCode(**values)

    def delete_oauth_code(self, code_id: str) -> bool:
        cursor = self.connection.execute("DELETE FROM oauth_codes WHERE code = ?", (code_id,))
        return cursor.rowcount > 0

    def delete_expired_oauth_codes(self, before: int) -> int:
        """Codes are single-use and short-lived; unredeemed ones are just litter."""
        cursor = self.connection.execute(
            "DELETE FROM oauth_codes WHERE created_at < ?", (before,)
        )
        return cursor.rowcount

    # -- refresh tokens -------------------------------------------------------

    def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        self.connection.execute(
            """
            INSERT INTO refresh_tokens (
                token_id, uid, client_id, scope, created_at, last_used_at
            ) VALUES (
                :token_id, :uid, :client_id, :scope, :created_at, :last_used_at
            )
            """,
            _as_row(token),
        )
        return token

    def refresh_token(self, token_id: str) -> RefreshToken | None:
        return _one(
            RefreshToken,
            self.connection.execute(
                "SELECT * FROM refresh_tokens WHERE token_id = ?", (token_id,)
            ),
        )

    def refresh_tokens(self, uid: str) -> list[RefreshToken]:
        rows = self.connection.execute(
            "SELECT * FROM refresh_tokens WHERE uid = ? ORDER BY created_at", (uid,)
        )
        return [RefreshToken(**dict(row)) for row in rows]

    def touch_refresh_token(self, token_id: str, at: int) -> None:
        self.connection.execute(
            "UPDATE refresh_tokens SET last_used_at = ? WHERE token_id = ?", (at, token_id)
        )

    def delete_refresh_token(self, token_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM refresh_tokens WHERE token_id = ?", (token_id,)
        )
        return cursor.rowcount > 0

    # -- sync users -----------------------------------------------------------

    def sync_users(self, fxa_uid: str) -> list[SyncUser]:
        """Every Sync uid this account has held, most recent first.

        The ordering is the tokenserver's definition of "current": greatest
        generation, then most recently created. Everything after the first
        element is history — a client state that has been retired, and storage
        waiting to be reclaimed.
        """
        rows = self.connection.execute(
            """
            SELECT * FROM sync_users WHERE fxa_uid = ?
            ORDER BY generation DESC, created_at DESC, uid DESC
            """,
            (fxa_uid,),
        )
        return [SyncUser(**dict(row)) for row in rows]

    def sync_user(self, uid: int) -> SyncUser | None:
        """One Sync uid, live or retired.

        The storage tier looks a user up by this number and nothing else: a
        token names it, and the row's continued existence is the only thing
        standing between an access token that outlived its account and a
        directory of records belonging to whoever gets that uid next.
        """
        return _one(
            SyncUser, self.connection.execute("SELECT * FROM sync_users WHERE uid = ?", (uid,))
        )

    def create_sync_user(
        self,
        *,
        fxa_uid: str,
        client_state: str,
        generation: int,
        keys_changed_at: int | None,
        created_at: int,
    ) -> SyncUser:
        """Allocate the next Sync uid. SQLite assigns it; we read it back."""
        cursor = self.connection.execute(
            """
            INSERT INTO sync_users (
                fxa_uid, client_state, generation, keys_changed_at, created_at, replaced_at
            ) VALUES (?, ?, ?, ?, ?, NULL)
            """,
            (fxa_uid, client_state, generation, keys_changed_at, created_at),
        )
        return SyncUser(
            uid=int(cursor.lastrowid or 0),
            fxa_uid=fxa_uid,
            client_state=client_state,
            generation=generation,
            keys_changed_at=keys_changed_at,
            created_at=created_at,
            replaced_at=None,
        )

    def update_sync_user(self, uid: int, *, generation: int, keys_changed_at: int | None) -> None:
        """Move a row forward in time. Both values are monotonic by the time we get here."""
        self.connection.execute(
            "UPDATE sync_users SET generation = ?, keys_changed_at = ? WHERE uid = ?",
            (generation, keys_changed_at, uid),
        )

    def replace_sync_user(self, uid: int, replaced_at: int) -> None:
        self.connection.execute(
            "UPDATE sync_users SET replaced_at = ? WHERE uid = ? AND replaced_at IS NULL",
            (replaced_at, uid),
        )

    def replace_other_sync_users(self, fxa_uid: str, *, keep: int, replaced_at: int) -> int:
        """Retire every row for this account except `keep`."""
        cursor = self.connection.execute(
            """
            UPDATE sync_users SET replaced_at = ?
            WHERE fxa_uid = ? AND uid != ? AND replaced_at IS NULL
            """,
            (replaced_at, fxa_uid, keep),
        )
        return cursor.rowcount

    # -- devices --------------------------------------------------------------

    def upsert_device(self, device: Device) -> Device:
        row = _as_row(device)
        row["available_commands"] = json.dumps(device.available_commands, separators=(",", ":"))
        row["push_endpoint_expired"] = int(device.push_endpoint_expired)
        self.connection.execute(
            """
            INSERT INTO devices (
                id, uid, session_token_id, refresh_token_id, name, type, created_at,
                push_callback, push_public_key, push_auth_key, push_endpoint_expired,
                available_commands
            ) VALUES (
                :id, :uid, :session_token_id, :refresh_token_id, :name, :type, :created_at,
                :push_callback, :push_public_key, :push_auth_key, :push_endpoint_expired,
                :available_commands
            )
            ON CONFLICT(id) DO UPDATE SET
                session_token_id      = excluded.session_token_id,
                refresh_token_id      = excluded.refresh_token_id,
                name                  = excluded.name,
                type                  = excluded.type,
                push_callback         = excluded.push_callback,
                push_public_key       = excluded.push_public_key,
                push_auth_key         = excluded.push_auth_key,
                push_endpoint_expired = excluded.push_endpoint_expired,
                available_commands    = excluded.available_commands
            """,
            row,
        )
        return device

    def device(self, uid: str, device_id: str) -> Device | None:
        row = self.connection.execute(
            "SELECT * FROM devices WHERE uid = ? AND id = ?", (uid, device_id)
        ).fetchone()
        return _device(row) if row else None

    def device_by_session_token(self, token_id: str) -> Device | None:
        row = self.connection.execute(
            "SELECT * FROM devices WHERE session_token_id = ?", (token_id,)
        ).fetchone()
        return _device(row) if row else None

    def device_by_refresh_token(self, token_id: str) -> Device | None:
        row = self.connection.execute(
            "SELECT * FROM devices WHERE refresh_token_id = ?", (token_id,)
        ).fetchone()
        return _device(row) if row else None

    def devices(self, uid: str) -> list[Device]:
        rows = self.connection.execute(
            "SELECT * FROM devices WHERE uid = ? ORDER BY created_at", (uid,)
        )
        return [_device(row) for row in rows]

    def delete_device(self, uid: str, device_id: str) -> Device | None:
        """Delete a device and, with it, the credential that registered it.

        Whichever of the two pointers the record carries: the session token for
        a desktop browser, the refresh token for a mobile one (`devices.destroy`
        revokes it through `oauthDB.removeRefreshToken`).  That is what makes
        "disconnect this device" actually disconnect it rather than log it out
        until its next request.
        """
        device = self.device(uid, device_id)
        if device is None:
            return None
        with self.transaction() as connection:
            connection.execute("DELETE FROM devices WHERE uid = ? AND id = ?", (uid, device_id))
            if device.session_token_id:
                connection.execute(
                    "DELETE FROM session_tokens WHERE token_id = ?", (device.session_token_id,)
                )
            if device.refresh_token_id:
                connection.execute(
                    "DELETE FROM refresh_tokens WHERE token_id = ?", (device.refresh_token_id,)
                )
        return device


class AccountExistsError(Exception):
    """Raised by `create_account` when the normalized email is already taken."""

    def __init__(self, email: str) -> None:
        super().__init__(f"account already exists: {email}")
        self.email = email


def normalize_email(email: str) -> str:
    """Case-folded lookup key. Upstream lowercases; the local part is not really
    case-insensitive, but every FxA client already assumes it is."""
    return email.strip().lower()


def open_database(path: str | Path) -> Database:
    """Open (creating if needed) and migrate a database."""
    database = Database(path)
    database.migrate()
    return database


def _as_row(record: Any) -> dict[str, Any]:
    return {slot: getattr(record, slot) for slot in record.__slots__}


def _one(kind: type, cursor: sqlite3.Cursor) -> Any:
    row = cursor.fetchone()
    return kind(**dict(row)) if row else None


def _device(row: sqlite3.Row) -> Device:
    values = dict(row)
    values["available_commands"] = json.loads(values["available_commands"])
    values["push_endpoint_expired"] = bool(values["push_endpoint_expired"])
    return Device(**values)
