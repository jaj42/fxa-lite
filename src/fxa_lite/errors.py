"""The FxA error envelope, and the subset of `errno`s fxa-lite can raise.

Every error the reference server returns carries the same JSON body — `code`,
`errno`, `error`, `message`, `info`, plus whatever extra keys the specific
error attaches (`libs/accounts/errors/src/app-error.ts`).  Clients branch on
`errno`, never on the HTTP status: `errno: 102` is how Firefox learns an
account is unknown, and `errno: 110` is how it learns a token went stale and
it should re-authenticate.  Getting those two numbers wrong is the difference
between a re-login prompt and an infinite retry loop.

Only the errnos fxa-lite can actually produce are listed.  The full table runs
to 230-odd values, most of them about subscriptions, 2FA and email delivery —
features that are deliberately out of scope.
"""

from __future__ import annotations

from typing import Any

#: `DEFAULT_ERRROR.info` upstream (their typo, not ours) — a documentation link
#: echoed on every error.
INFO_URL = "https://mozilla.github.io/ecosystem-platform/api#section/Response-format"


class Errno:
    """`ERRNO` from `libs/accounts/errors/src/constants.ts`, trimmed to what we raise."""

    SERVER_CONFIG_ERROR = 100
    ACCOUNT_EXISTS = 101
    ACCOUNT_UNKNOWN = 102
    INCORRECT_PASSWORD = 103
    ACCOUNT_UNVERIFIED = 104
    INVALID_PARAMETER = 107
    MISSING_PARAMETER = 108
    INVALID_REQUEST_SIGNATURE = 109
    INVALID_TOKEN = 110
    REQUEST_TOO_LARGE = 113
    ENDPOINT_NOT_SUPPORTED = 116
    INCORRECT_EMAIL_CASE = 120
    DEVICE_UNKNOWN = 123
    DEVICE_CONFLICT = 124
    UNKNOWN_CLIENT_ID = 162
    INVALID_SCOPES = 163
    SERVER_BUSY = 201
    FEATURE_NOT_ENABLED = 202
    UNEXPECTED_ERROR = 999


class FxaError(Exception):
    """An error with a wire representation. Raised by routes, rendered by `app.py`."""

    def __init__(
        self,
        *,
        code: int,
        errno: int,
        error: str,
        message: str,
        headers: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.errno = errno
        self.error = error
        self.message = message
        self.headers = headers or {}
        #: Error-specific keys merged into the payload (`email`, `retryAfter`, …).
        self.extra = {key: value for key, value in extra.items() if value is not None}

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "errno": self.errno,
            "error": self.error,
            "message": self.message,
            "info": INFO_URL,
            **self.extra,
        }


def _bad_request(errno: int, message: str, **extra: Any) -> FxaError:
    return FxaError(code=400, errno=errno, error="Bad Request", message=message, **extra)


def account_exists(email: str | None = None) -> FxaError:
    return _bad_request(Errno.ACCOUNT_EXISTS, "Account already exists", email=email)


def unknown_account(email: str | None = None) -> FxaError:
    return _bad_request(Errno.ACCOUNT_UNKNOWN, "Unknown account", email=email)


def incorrect_password(db_email: str, request_email: str) -> FxaError:
    """Mismatched case gets its own errno so the client can retry with the stored spelling."""
    if db_email != request_email:
        return _bad_request(Errno.INCORRECT_EMAIL_CASE, "Incorrect email case", email=db_email)
    return _bad_request(Errno.INCORRECT_PASSWORD, "Incorrect password", email=db_email)


def unverified_account() -> FxaError:
    return _bad_request(Errno.ACCOUNT_UNVERIFIED, "Unconfirmed account")


def invalid_request_parameter(validation: Any = None) -> FxaError:
    return _bad_request(
        Errno.INVALID_PARAMETER, "Invalid parameter in request body", validation=validation
    )


def missing_request_parameter(param: str | None = None) -> FxaError:
    suffix = f": {param}" if param else ""
    return _bad_request(
        Errno.MISSING_PARAMETER, f"Missing parameter in request body{suffix}", param=param
    )


def invalid_signature(message: str = "Invalid signature") -> FxaError:
    return _bad_request(Errno.INVALID_REQUEST_SIGNATURE, message)


def invalid_token(message: str | None = None) -> FxaError:
    return FxaError(
        code=401,
        errno=Errno.INVALID_TOKEN,
        error="Unauthorized",
        message=message or "Invalid authentication token in request signature",
    )


def unauthorized(reason: str | None = None) -> FxaError:
    """A failed token lookup. `errno` stays 110 so a 401 always means "get a new token"."""
    return FxaError(
        code=401,
        errno=Errno.INVALID_TOKEN,
        error="Unauthorized",
        message="Unauthorized for route",
        detail=reason,
    )


def unknown_device() -> FxaError:
    return _bad_request(Errno.DEVICE_UNKNOWN, "Unknown device")


def device_session_conflict(device_id: str | None = None) -> FxaError:
    return _bad_request(
        Errno.DEVICE_CONFLICT, "Session already registered by another device", deviceId=device_id
    )


def request_body_too_large() -> FxaError:
    return FxaError(
        code=413,
        errno=Errno.REQUEST_TOO_LARGE,
        error="Request Entity Too Large",
        message="Request body too large",
    )


def feature_not_enabled(retry_after: int = 30) -> FxaError:
    return FxaError(
        code=403,
        errno=Errno.FEATURE_NOT_ENABLED,
        error="Feature not enabled",
        message="Feature not enabled",
        retryAfter=retry_after,
    )


def gone() -> FxaError:
    return FxaError(
        code=410,
        errno=Errno.ENDPOINT_NOT_SUPPORTED,
        error="Gone",
        message="This endpoint is no longer supported",
    )


def service_unavailable(retry_after: int = 30) -> FxaError:
    return FxaError(
        code=503,
        errno=Errno.SERVER_BUSY,
        error="Service Unavailable",
        message="Service unavailable",
        retryAfter=retry_after,
    )


def unexpected_error() -> FxaError:
    return FxaError(
        code=500,
        errno=Errno.UNEXPECTED_ERROR,
        error="Internal Server Error",
        message="Unspecified error",
    )
