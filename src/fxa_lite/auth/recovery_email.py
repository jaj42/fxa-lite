"""`/v1/recovery_email/status` — the poll Firefox will not stop making.

Desktop polls this endpoint after sign-in and refuses to move on until
`verified` is true.  There is no mailer here and no confirmation link to click,
so the only honest answer is the one that is also the only workable one:
accounts and their sessions are verified at creation, and this says so.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from .credentials import Session

router = APIRouter(tags=["recovery_email"])


@router.get("/recovery_email/status")
def recovery_email_status(
    credentials: Session,
    reason: str | None = Query(default=None, max_length=16),
) -> dict[str, Any]:
    return {
        "email": credentials.account.email,
        "verified": True,
        "sessionVerified": True,
        "emailVerified": True,
    }
