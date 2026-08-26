# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The tokenserver's error envelope — which is not the accounts API's.

`syncstorage-rs/tokenserver-common/src/error.rs`.  Everything else fxa-lite
serves answers with `{code, errno, error, message, info}`; the tokenserver
answers with

    {"status": "...", "errors": [{"location": ..., "name": ..., "description": ...}]}

because it grew out of a Pyramid/cornice service and never converged with the
Node stack.  Firefox has two separate parsers for the two shapes, so the split
has to be reproduced rather than tidied away.

`status` is the field that carries meaning.  `invalid-client-state` tells the
client its Sync key no longer matches what the server has seen and it should
re-authenticate; `invalid-generation` and `invalid-keysChangedAt` say the
credentials are stale in the other direction.  A generic 401 would leave
Firefox retrying the same dead token forever.
"""

from __future__ import annotations

from typing import Any


class TokenserverError(Exception):
    """An error with the tokenserver's wire representation."""

    def __init__(
        self,
        *,
        status: str = "error",
        location: str = "header",
        name: str = "",
        description: str = "Unauthorized",
        http_status: int = 401,
    ) -> None:
        super().__init__(description)
        self.status = status
        self.location = location
        self.name = name
        self.description = description
        self.http_status = http_status

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": [
                {
                    "location": self.location,
                    "name": self.name,
                    "description": self.description,
                }
            ],
        }


def invalid_credentials(description: str = "Unauthorized") -> TokenserverError:
    """The catch-all for a token we will not accept: absent, malformed, or unsigned."""
    return TokenserverError(
        status="invalid-credentials", location="body", description=description
    )


def unauthorized(description: str = "Unauthorized") -> TokenserverError:
    """`status: "error"` — used where upstream leaves the default status in place."""
    return TokenserverError(location="body", description=description)


def invalid_key_id(description: str) -> TokenserverError:
    return TokenserverError(status="invalid-key-id", description=description)


def invalid_client_state(description: str) -> TokenserverError:
    """The client's key fingerprint is one we cannot accept for this account."""
    return TokenserverError(
        status="invalid-client-state", name="X-Client-State", description=description
    )


def invalid_generation(description: str = "Unauthorized") -> TokenserverError:
    return TokenserverError(status="invalid-generation", location="body", description=description)


def invalid_keys_changed_at(description: str = "Unauthorized") -> TokenserverError:
    return TokenserverError(
        status="invalid-keysChangedAt", location="body", description=description
    )


def bad_client_state_header() -> TokenserverError:
    """A malformed `X-Client-State` is a 400, not a 401: nothing was authenticated yet."""
    return TokenserverError(
        location="header",
        name="X-Client-State",
        description="Invalid client state value",
        http_status=400,
    )


def unsupported(description: str, name: str) -> TokenserverError:
    """A path below `/token` that names an application or version we do not serve."""
    return TokenserverError(location="url", name=name, description=description, http_status=404)


def internal_error() -> TokenserverError:
    return TokenserverError(
        status="internal-error", location="internal", description="Server error", http_status=500
    )


__all__ = [
    "TokenserverError",
    "bad_client_state_header",
    "internal_error",
    "invalid_client_state",
    "invalid_credentials",
    "invalid_generation",
    "invalid_key_id",
    "invalid_keys_changed_at",
    "unauthorized",
    "unsupported",
]
