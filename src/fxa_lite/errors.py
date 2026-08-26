# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
    THROTTLED = 114
    ENDPOINT_NOT_SUPPORTED = 116
    INCORRECT_EMAIL_CASE = 120
    DEVICE_UNKNOWN = 123
    DEVICE_CONFLICT = 124
    UNKNOWN_CLIENT_ID = 162
    INVALID_SCOPES = 163
    NOT_PUBLIC_CLIENT = 166
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


def client_not_public() -> FxaError:
    """`AppError.notPublicClient` — the *auth* tier's spelling of it.

    The OAuth tier has its own (`not_public_client`, errno 116 in that table);
    this is the one the refresh-token auth scheme raises, errno 166, and the
    two are different numbers for the same sentence.
    """
    return _bad_request(Errno.NOT_PUBLIC_CLIENT, "Not a public client")


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


def too_many_requests(retry_after: int) -> FxaError:
    """`AppError.tooManyRequests` — the customs server's answer, ours by hand.

    Both the `retryAfter` body field and the `Retry-After` header are sent,
    which `feature_not_enabled` below deliberately refuses to do. The
    difference is that this one is true: Firefox reads the header in
    `HawkClient._constructError`, caches the value as `backoffError` and stops
    sending FxA requests until it expires — exactly the behaviour wanted from a
    client that has just failed a password check ten times, and exactly the
    behaviour not wanted from an answer that will never change.
    """
    return FxaError(
        code=429,
        errno=Errno.THROTTLED,
        error="Too Many Requests",
        message="Client has sent too many requests",
        headers={"Retry-After": str(retry_after)},
        retryAfter=retry_after,
    )


# DIVERGENCE: no-retry-after-on-permanent-403 — errno 202 carries no `retryAfter`
#   upstream: `AppError.featureNotEnabled` defaults `retryAfter` to 30 and sets
#     a `Retry-After` header with it.
#   fxa-lite: both absent unless a caller asks for them, and no caller does.
#   why: Firefox's `FxAccountsClient._request` caches a `retryAfter` from any
#     error body as `backoffError` and then rejects *every* FxA request for that
#     long, refreshed on each retry. On an answer that will never change, that
#     stalls the whole account client on a timer. Upstream can afford the
#     default because its switch is temporary; these features are off by
#     construction.
#   cost: a client polling a permanently-disabled feature is not told to slow
#     down, so it polls at its own interval. That is two requests a minute for
#     one route, against stalling sign-in.
def feature_not_enabled(retry_after: int | None = None) -> FxaError:
    """403 for a feature this deployment does not run.

    **`retryAfter` defaults to absent here, where upstream defaults to 30** —
    and upstream also sets a `Retry-After` header. Both are load-bearing in
    Firefox and neither is safe on an answer that will never change:
    `HawkClient._constructError` reads the header and, on any status, notifies
    `fxaccounts:backoff:interval`; and when the body carries an `error` key —
    which this envelope always does — `hawkclient.request` throws the parsed
    body itself, so `FxAccountsClient._request` sees `error.retryAfter`, caches
    it as `backoffError` and rejects *every* FxA request for that many seconds.
    A feature that is permanently off would therefore stall the whole account
    client on a timer, refreshed each time the client asked again.

    Upstream can afford both because `deviceNotificationsEnabled` is a safety
    switch it expects to flip back ("in case problems with the client logic
    cause server overload"); fxa-lite's features are off by construction.
    """
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


class OauthErrno:
    """`OAUTH_ERRNO` — a **separate** numbering from `Errno` above.

    The OAuth routes are a merged-in second service upstream, and they kept
    their own error table: on `/v1/oauth/*`, `/v1/verify` and friends, `errno`
    means what this class says, not what `Errno` says. `108` is "invalid token"
    here and "missing parameter" there. The two never appear on one route, so
    the ambiguity is the client's to resolve by knowing which endpoint it
    called — which is exactly how the reference leaves it.
    """

    UNKNOWN_CLIENT = 101
    INCORRECT_SECRET = 102
    INCORRECT_REDIRECT = 103
    INVALID_ASSERTION = 104
    UNKNOWN_CODE = 105
    INCORRECT_CODE = 106
    EXPIRED_CODE = 107
    INVALID_TOKEN = 108
    INVALID_PARAMETER = 109
    INVALID_RESPONSE_TYPE = 110
    UNAUTHORIZED = 111
    FORBIDDEN = 112
    INVALID_CONTENT_TYPE = 113
    INVALID_SCOPES = 114
    EXPIRED_TOKEN = 115
    NOT_PUBLIC_CLIENT = 116
    INCORRECT_CODE_CHALLENGE = 117
    MISSING_PKCE_PARAMETERS = 118
    STALE_AUTH_AT = 119
    MISMATCH_ACR_VALUES = 120
    INVALID_GRANT_TYPE = 121
    UNKNOWN_TOKEN = 122
    SERVER_UNAVAILABLE = 201
    DISABLED_CLIENT_ID = 202


def _oauth_bad_request(errno: int, message: str, **extra: Any) -> FxaError:
    return FxaError(code=400, errno=errno, error="Bad Request", message=message, **extra)


def unknown_client(client_id: str) -> FxaError:
    return _oauth_bad_request(OauthErrno.UNKNOWN_CLIENT, "Unknown client", clientId=client_id)


def incorrect_redirect(redirect_uri: str | None) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.INCORRECT_REDIRECT, "Incorrect redirect_uri", redirectUri=redirect_uri
    )


def unknown_code(code: str) -> FxaError:
    return _oauth_bad_request(OauthErrno.UNKNOWN_CODE, "Unknown code", requestCode=code)


def mismatch_code(code: str, client_id: str) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.INCORRECT_CODE, "Incorrect code", requestCode=code, client=client_id
    )


def expired_code(code: str, expired_at: int) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.EXPIRED_CODE, "Expired code", requestCode=code, expiredAt=expired_at
    )


def oauth_invalid_token() -> FxaError:
    """400, not 401: on the OAuth tier a bad token is a bad parameter."""
    return _oauth_bad_request(OauthErrno.INVALID_TOKEN, "Invalid token")


def oauth_invalid_request_parameter(validation: Any = None) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.INVALID_PARAMETER, "Invalid request parameter", validation=validation
    )


def invalid_response_type() -> FxaError:
    return _oauth_bad_request(OauthErrno.INVALID_RESPONSE_TYPE, "Invalid response_type")


def invalid_scopes(scopes: list[str]) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.INVALID_SCOPES, "Requested scopes are not allowed", invalidScopes=scopes
    )


def not_public_client(client_id: str) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.NOT_PUBLIC_CLIENT, "Not a public client", clientId=client_id
    )


def mismatch_code_challenge(pkce_hash: str | None) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.INCORRECT_CODE_CHALLENGE, "Incorrect code_challenge", pkceHashValue=pkce_hash
    )


def missing_pkce_parameters() -> FxaError:
    return _oauth_bad_request(
        OauthErrno.MISSING_PKCE_PARAMETERS, "Public clients require PKCE OAuth parameters"
    )


def stale_auth_at(auth_at: int) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.STALE_AUTH_AT, "Stale authentication timestamp", authAt=auth_at
    )


def invalid_grant_type() -> FxaError:
    return _oauth_bad_request(OauthErrno.INVALID_GRANT_TYPE, "Invalid grant_type")


def mismatch_acr_values(found: str) -> FxaError:
    return _oauth_bad_request(
        OauthErrno.MISMATCH_ACR_VALUES, "Mismatch acr value", foundValue=found
    )


def expired_token(expired_at: int) -> FxaError:
    return _oauth_bad_request(OauthErrno.EXPIRED_TOKEN, "Expired token", expiredAt=expired_at)


def unknown_token() -> FxaError:
    return _oauth_bad_request(OauthErrno.UNKNOWN_TOKEN, "Unknown token")


class ProfileErrno:
    """A *third* errno table — the profile server's (`fxa-profile-server/lib/error.js`).

    Only two values matter here. Insufficient scope has no errno of its own
    upstream: hapi answers 403 and the translation layer stamps it 999. Reusing
    `UNAUTHORIZED` and separating the two cases by status code says more.
    """

    UNAUTHORIZED = 100
    INVALID_PARAMETER = 101


def profile_unauthorized(reason: str | None = None) -> FxaError:
    return FxaError(
        code=401,
        errno=ProfileErrno.UNAUTHORIZED,
        error="Bad Request",
        message="Unauthorized",
        reason=reason,
    )


def insufficient_scope(required: list[str]) -> FxaError:
    return FxaError(
        code=403,
        errno=ProfileErrno.UNAUTHORIZED,
        error="Forbidden",
        message="Insufficient scope",
        requiredScope=required,
    )
