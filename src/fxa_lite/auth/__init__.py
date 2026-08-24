"""The accounts API: everything Firefox talks to before OAuth gets involved.

Mounted at `/v1`, matching the reference auth server's own prefix.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import account, devices, recovery_email, session, util


def router() -> APIRouter:
    api = APIRouter()
    for module in (account, session, recovery_email, devices, util):
        api.include_router(module.router)
    return api


__all__ = ["router"]
