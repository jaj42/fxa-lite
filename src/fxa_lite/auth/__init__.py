# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The accounts API: everything Firefox talks to before OAuth gets involved.

Mounted at `/v1`, matching the reference auth server's own prefix.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import account, attached_clients, devices, recovery_email, session, util


def router() -> APIRouter:
    api = APIRouter()
    for module in (account, session, recovery_email, devices, attached_clients, util):
        api.include_router(module.router)
    return api


__all__ = ["router"]
