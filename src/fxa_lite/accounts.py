# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Account lifecycle: provisioning, password checks, session and key tokens.

The CLI and the accounts API need exactly the same steps in exactly the same
order, so they live here rather than in either caller.  `fxa-lite account add`
holds the plaintext password and has to do the client's half of the onepw
protocol itself; `POST /v1/account/create` receives `authPW` already stretched.
Both then land in `provision`.

Nothing here knows about HTTP.  Failures raise `errors.FxaError`, because the
errno *is* the domain vocabulary — `102` means unknown account whether it
surfaces on the wire or on a terminal.
"""

from __future__ import annotations

import secrets
import time

from . import errors
from .crypto import onepw
from .crypto.tokens import TokenKeys, TokenType, bundle_account_keys, new_token
from .db import Account, AccountExistsError, Database, KeyFetchToken, SessionToken, normalize_email
from .throttle import FailureThrottle

#: `password.js` hash version 1 — scrypt with the parameters in `crypto/onepw.py`.
VERIFIER_VERSION = 1


def now_ms() -> int:
    """Milliseconds since the epoch. Every timestamp on the wire is in these units."""
    return int(time.time() * 1000)


def provision(
    db: Database,
    *,
    email: str,
    auth_pw: bytes,
    locale: str | None = None,
) -> tuple[Account, onepw.StretchedPassword]:
    """Create an account from an already-stretched `authPW`.

    The account is created verified: there is no mailer to confirm it with, and
    Firefox polls `/v1/recovery_email/status` forever if `verified` is false.

    The stretched password comes back with the account so that a caller wanting
    a key fetch token in the same request need not pay for scrypt twice.
    """
    created_at = now_ms()
    auth_salt = secrets.token_bytes(32)
    stretched = onepw.stretch(auth_pw, auth_salt)
    account = Account(
        uid=secrets.token_hex(16),
        email=email.strip(),
        normalized_email=normalize_email(email),
        email_code=secrets.token_hex(16),
        # kA is server-side key material the client only ever sees bundled.
        ka=secrets.token_hex(32),
        # With no v2 credentials in play the reference server stores a random
        # wrapWrapKb and lets kB fall out of it: kB = wrapKb XOR unwrapBKey,
        # where wrapKb = wrapper XOR wrapWrapKb. So kB is whatever those three
        # random-ish values imply, which is exactly as unguessable as it needs
        # to be, and nobody ever has to compute kB server-side.
        wrap_wrap_kb=secrets.token_hex(32),
        auth_salt=auth_salt.hex(),
        verify_hash=stretched.verify_hash.hex(),
        verifier_version=VERIFIER_VERSION,
        verifier_set_at=created_at,
        created_at=created_at,
        keys_changed_at=created_at,
        profile_changed_at=created_at,
        locale=locale,
    )
    try:
        db.create_account(account)
    except AccountExistsError as exc:
        raise errors.account_exists(exc.email) from exc
    return account, stretched


def provision_with_password(
    db: Database, *, email: str, password: str, locale: str | None = None
) -> Account:
    """Provision from a plaintext password, doing the client's stretching locally.

    Only the CLI takes this path. A v1 salt is used because it is the one every
    Firefox knows how to reproduce from the email address alone.
    """
    credentials = onepw.credentials_v1(email, password)
    account, _ = provision(db, email=email, auth_pw=credentials.auth_pw, locale=locale)
    return account


# DIVERGENCE: failed-login-throttle — what is left of the customs server
#   upstream: a separate service (fxa-customs-server) rate-limits by IP, email
#     and action, with block lists and unblock codes behind it.
#   fxa-lite: one in-process counter of *failed* password checks per normalized
#     email, consulted between the account lookup and scrypt; ten in five
#     minutes, then 429 / errno 114 with `retryAfter` and `Retry-After`.
#   why: scrypt at N=65536 is a denial-of-service amplifier before it is a
#     guessing surface. Counting failures rather than requests is what makes it
#     safe to ship on by default — an attacker cannot lock a household out of
#     its own accounts, because a correct password clears the tally.
#   cost: it does not limit by IP, because behind a reverse proxy every client
#     is 127.0.0.1; that half is the proxy's job and ships uncommented in
#     `deploy/nginx.conf.example`. It closes no account-existence oracle and is
#     not meant to.
def authenticate(
    db: Database,
    *,
    email: str,
    auth_pw: bytes,
    throttle: FailureThrottle | None = None,
) -> tuple[Account, onepw.StretchedPassword]:
    """Check `authPW` against the stored verify hash.

    Returns the stretched password too: unwrapping `wrapKb` for a key fetch
    token needs it, and scrypt is slow enough that doing it twice is rude.

    `throttle` is where the missing customs server lives. The order below is
    the point of it: the account lookup is one indexed SELECT, and an address
    with no account raises before `onepw.stretch` runs — so an unknown email
    cannot drive scrypt at all, and cannot put an entry in the throttle's table
    either. Only a *known* account whose password was wrong is counted, and
    only that account's own next attempt pays for it.
    """
    account = db.account_by_email(email)
    if account is None:
        raise errors.unknown_account(email)
    key = normalize_email(email)
    if throttle is not None:
        throttle.check(key)
    stretched = onepw.stretch(auth_pw, bytes.fromhex(account.auth_salt))
    if not stretched.matches(bytes.fromhex(account.verify_hash)):
        if throttle is not None:
            throttle.record_failure(key)
        # Passing the stored spelling lets a case-only mismatch answer errno 120
        # instead of 103, which is how clients know to retry rather than reprompt.
        raise errors.incorrect_password(account.email, email.strip())
    if throttle is not None:
        throttle.record_success(key)
    return account, stretched


def start_session(
    db: Database,
    account: Account,
    *,
    user_agent: str = "",
    auth_at: int | None = None,
) -> tuple[TokenKeys, SessionToken]:
    """Mint a session token. It is verified from birth — see `provision`.

    The stored record comes back alongside the keys because `authAt` on the
    wire has to be *this* token's, not a second `now()` a millisecond later.
    """
    created_at = now_ms()
    keys = new_token(TokenType.SESSION)
    token = db.create_session_token(
        SessionToken(
            token_id=keys.id.hex(),
            uid=account.uid,
            auth_key=keys.auth_key.hex(),
            created_at=created_at,
            auth_at=auth_at if auth_at is not None else created_at,
            last_access_time=created_at,
            user_agent=user_agent,
        )
    )
    return keys, token


def start_key_fetch(
    db: Database, account: Account, stretched: onepw.StretchedPassword
) -> TokenKeys:
    """Mint a key fetch token, bundling kA and wrapKb into it up front.

    The bundle is computed now and stored, exactly as `KeyFetchToken.create`
    does: the token is single-use, and the row is deleted when it is read, so
    the bundle has to outlive the plaintext key material it was built from.
    """
    keys = new_token(TokenType.KEY_FETCH)
    wrap_kb = stretched.wrap(bytes.fromhex(account.wrap_wrap_kb))
    bundle = bundle_account_keys(keys.bundle_key, bytes.fromhex(account.ka), wrap_kb)
    db.create_key_fetch_token(
        KeyFetchToken(
            token_id=keys.id.hex(),
            uid=account.uid,
            auth_key=keys.auth_key.hex(),
            key_bundle=bundle.hex(),
            created_at=now_ms(),
        )
    )
    return keys
