"""`/v1/account/*` — create, sign in, look up, fetch keys, delete.

The routes Firefox hits first, and the ones that decide whether it ever gets
as far as Sync.  Two answers matter more than the rest: `verified: true` on
login (there is no mailer, so an unverified account never becomes verified),
and the `bundle` from `/account/keys`, which is the only way `kB` reaches the
browser.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from .. import accounts, errors
from ..db import Database
from .credentials import KeyFetch, Session, database, optional_session_credentials
from .models import (
    AccountCreate,
    AccountDestroy,
    AccountLogin,
    AccountStatusCheck,
    CredentialsStatus,
)

router = APIRouter(tags=["account"])


@router.post("/account/create")
def account_create(
    payload: AccountCreate,
    request: Request,
    keys: bool = Query(default=False),
) -> dict[str, Any]:
    """Create an account and sign it in, in one round trip.

    fxa-lite has no signup funnel — accounts are normally provisioned with
    `fxa-lite account add` — but this is the endpoint the reference client
    exercises, so it stays wire-compatible and does exactly what the CLI does.
    """
    db = database(request)
    account, stretched = accounts.provision(
        db,
        email=payload.email,
        auth_pw=bytes.fromhex(payload.authPW),
        locale=request.headers.get("accept-language"),
    )
    session, token = accounts.start_session(
        db, account, user_agent=request.headers.get("user-agent", "")
    )
    response: dict[str, Any] = {
        "uid": account.uid,
        "sessionToken": session.token,
        "authAt": token.last_auth_at,
    }
    if keys:
        response["keyFetchToken"] = accounts.start_key_fetch(db, account, stretched).token
    return response


@router.post("/account/login")
def account_login(
    payload: AccountLogin,
    request: Request,
    keys: bool = Query(default=False),
) -> dict[str, Any]:
    db = database(request)
    account, stretched = accounts.authenticate(
        db, email=payload.email, auth_pw=bytes.fromhex(payload.authPW)
    )
    session, token = accounts.start_session(
        db, account, user_agent=request.headers.get("user-agent", "")
    )
    response: dict[str, Any] = {
        "uid": account.uid,
        "sessionToken": session.token,
        "authAt": token.last_auth_at,
        # Accounts and their sessions are verified from birth: nothing can ever
        # confirm them later, and Firefox polls /recovery_email/status until
        # `verified` is true.
        "verified": True,
        "emailVerified": True,
        "sessionVerified": True,
        # No metrics pipeline exists here, so telling a client metrics are on
        # would be a lie it acts on.
        "metricsEnabled": False,
    }
    if keys:
        response["keyFetchToken"] = accounts.start_key_fetch(db, account, stretched).token
    return response


@router.get("/account/status")
def account_status(
    request: Request,
    uid: str | None = Query(default=None, pattern=r"^[a-fA-F0-9]{32}$"),
) -> dict[str, Any]:
    """Authenticated: describe this session's account. Anonymous: does `uid` exist?"""
    credentials = optional_session_credentials(request)
    if credentials is not None:
        return {
            "exists": True,
            "locale": credentials.account.locale,
            "hasPassword": credentials.account.verifier_set_at > 0,
        }
    if uid is None:
        raise errors.missing_request_parameter("uid")
    return {"exists": database(request).account(uid) is not None}


@router.post("/account/status")
def account_status_check(payload: AccountStatusCheck, request: Request) -> dict[str, Any]:
    account = database(request).account_by_email(payload.email)
    return {
        "exists": account is not None,
        "hasPassword": account is not None,
        # Third-party sign-in and passkeys are out of scope; saying so plainly
        # keeps a client from offering a button that cannot work.
        "hasLinkedAccount": False,
        "hasPasskey": False,
    }


@router.get("/account/profile")
def account_profile(credentials: Session) -> dict[str, Any]:
    account = credentials.account
    return {
        "email": account.email,
        "locale": account.locale,
        # 'pwd' and 'email' are what the reference reports for a password-only
        # account; there is no second factor here to raise the level above 1.
        "authenticationMethods": ["pwd", "email"],
        "authenticatorAssuranceLevel": 1,
        "profileChangedAt": account.profile_changed_at,
        "keysChangedAt": account.keys_changed_at,
        "metricsEnabled": False,
    }


@router.get("/account/keys")
def account_keys(request: Request, credentials: KeyFetch) -> dict[str, Any]:
    """Hand over `kA || wrapKb`, once.

    The bundle was sealed when the token was minted; all that is left is to
    return it and destroy the token, so a replay finds nothing.
    """
    db: Database = database(request)
    db.delete_key_fetch_token(credentials.token.token_id)
    return {"bundle": credentials.token.key_bundle}


@router.post("/account/destroy")
def account_destroy(
    payload: AccountDestroy, request: Request, credentials: Session
) -> dict[str, Any]:
    db = database(request)
    account, _ = accounts.authenticate(
        db, email=payload.email, auth_pw=bytes.fromhex(payload.authPW)
    )
    if account.uid != credentials.account.uid:
        raise errors.unknown_account(payload.email)
    db.delete_account(account.uid)
    return {}


@router.post("/account/credentials/status")
def credentials_status(payload: CredentialsStatus, request: Request) -> dict[str, Any]:
    """Which key-stretching version this account uses.

    Always v1, and never `upgradeNeeded`. Upstream reports `upgradeNeeded` when
    an account has no v2 verifier, which asks the client to run a password
    change it can only complete against a server that speaks v2. fxa-lite does
    not, so promising an upgrade would strand the client mid-flow.
    """
    account = database(request).account_by_email(payload.email)
    if account is None:
        raise errors.unknown_account(payload.email)
    return {"currentVersion": "v1", "upgradeNeeded": False}
