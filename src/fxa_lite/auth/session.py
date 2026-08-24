"""`/v1/session/*` — the lifecycle of a signed-in session.

`duplicate` is the one with a subtlety: the new token copies the *original's*
creation time, because `authAt` is derived from it and a fresh timestamp would
claim the user just typed their password when they did not.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from .. import accounts, errors
from ..crypto.tokens import TokenType, derive_token_keys, new_token
from ..db import SessionToken
from .credentials import Session, database
from .models import SessionDestroy, SessionDuplicate, SessionReauth

router = APIRouter(tags=["session"])


@router.get("/session/status")
def session_status(credentials: Session) -> dict[str, Any]:
    return {
        "state": "verified",
        "uid": credentials.account.uid,
        "details": {
            "accountEmailVerified": True,
            "sessionVerificationMethod": None,
            "sessionVerified": True,
            "sessionVerificationMeetsMinimumAAL": True,
            "verified": True,
        },
    }


@router.post("/session/destroy")
def session_destroy(
    request: Request, credentials: Session, payload: SessionDestroy | None = None
) -> dict[str, Any]:
    """Sign out. `customSessionToken` lets one session end another of its own account."""
    db = database(request)
    token_id = credentials.token.token_id
    if payload is not None and payload.customSessionToken:
        target = db.session_token(
            derive_token_keys(TokenType.SESSION, bytes.fromhex(payload.customSessionToken)).id.hex()
        )
        if target is None or target.uid != credentials.account.uid:
            raise errors.invalid_token("Invalid session token")
        token_id = target.token_id
    db.delete_session_token(token_id)
    return {}


@router.post("/session/duplicate")
def session_duplicate(
    request: Request, credentials: Session, payload: SessionDuplicate | None = None
) -> dict[str, Any]:
    """Fork this session into a second token with the same authentication history."""
    db = database(request)
    original = credentials.token
    keys = new_token(TokenType.SESSION)
    duplicate = SessionToken(
        token_id=keys.id.hex(),
        uid=original.uid,
        auth_key=keys.auth_key.hex(),
        # Copied, not refreshed: see the module docstring.
        created_at=original.created_at,
        auth_at=original.auth_at,
        last_access_time=accounts.now_ms(),
        user_agent=request.headers.get("user-agent", original.user_agent),
    )
    db.create_session_token(duplicate)
    return {
        "uid": duplicate.uid,
        "sessionToken": keys.token,
        "authAt": duplicate.last_auth_at,
        "emailVerified": True,
        "sessionVerified": True,
        "verified": True,
    }


@router.post("/session/reauth")
def session_reauth(
    payload: SessionReauth,
    request: Request,
    credentials: Session,
    keys: bool = Query(default=False),
) -> dict[str, Any]:
    """Re-prove the password on an existing session, optionally getting fresh keys.

    Unlike `/account/login` this mints no new session token — the point is to
    refresh `authAt` on the one already in hand.
    """
    db = database(request)
    account, stretched = accounts.authenticate(
        db, email=payload.email, auth_pw=bytes.fromhex(payload.authPW)
    )
    if account.uid != credentials.account.uid:
        raise errors.unknown_account(payload.email)

    auth_at = accounts.now_ms()
    db.reauthenticate_session_token(credentials.token.token_id, auth_at)
    response: dict[str, Any] = {
        "uid": account.uid,
        "authAt": auth_at // 1000,
        "verified": True,
        "emailVerified": True,
        "sessionVerified": True,
        "metricsEnabled": False,
    }
    if keys:
        response["keyFetchToken"] = accounts.start_key_fetch(db, account, stretched).token
    return response
