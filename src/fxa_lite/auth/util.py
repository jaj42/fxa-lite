"""`lib/routes/util.js` — the one utility route worth keeping."""

from __future__ import annotations

import secrets

from fastapi import APIRouter

router = APIRouter(tags=["util"])


@router.post("/get_random_bytes")
def get_random_bytes() -> dict[str, str]:
    """32 bytes of entropy, for clients that would rather trust the server's CSPRNG."""
    return {"data": secrets.token_hex(32)}
