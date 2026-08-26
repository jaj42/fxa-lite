# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""FastAPI assembly: routers, error rendering, lifespan.

One app, one origin.  The accounts and OAuth APIs mount at `/v1` — the prefix
the reference auth server uses, and the one it serves OAuth from too — the
profile server at `/profile/v1`, the Sync tokenserver at `/token`, Sync
storage at `/storage`, and the sign-in page, its assets and the discovery
documents at the root.
`/.well-known/fxa-client-configuration` tells Firefox where each of those is,
so the layout is ours to choose; see `wellknown.py`.

The content router is included last, and `/` belongs to it: that is the URL
Firefox opens to sign in.

Three middlewares wrap the lot, outermost first.  `tracing.Trace` does nothing
at the default log level; at `debug` it writes a redacted rendering of every
request and response, which is the only practical way to see why a client the
size of Firefox is unhappy.  `middleware.SecurityHeaders` stamps `nosniff` and
a null CSP on whatever has not set its own.  `middleware.BodyLimit` refuses an
oversized request body before anything reads it — a route function is far too
late, because by then the body is buffered.

The error handlers matter as much as the routes.  A client reads `errno`, not
the HTTP status, so an unhandled exception that escapes as FastAPI's default
`{"detail": ...}` is not "a 500 with a different body" — it is a response the
client cannot interpret at all.  Everything is funnelled through
`errors.FxaError` — except the tokenserver and Sync storage, each of which
has always spoken a different envelope and gets its own handler.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException

from . import (
    __version__,
    auth,
    content,
    errors,
    middleware,
    profile,
    syncstorage,
    tokenserver,
    tracing,
    wellknown,
)
from .config import Config
from .db import Database, open_database
from .oauth import routes as oauth_routes
from .oauth.clients import Registry
from .oauth.keys import SigningKeys
from .oauth.keys import load as load_signing_keys
from .throttle import FailureThrottle
from .tokenserver import tokenlib

#: The prefix the reference auth server serves its API from. The OAuth routes
#: share it: upstream they are one process behind one prefix, and Firefox's
#: `oauth_server_base_url` and `auth_server_base_url` may well be the same host.
API_PREFIX = "/v1"
#: `fxa-profile-server`'s own prefix, below a mount of our choosing.
PROFILE_PREFIX = "/profile/v1"
#: What `sync_tokenserver_base_url` points at; Firefox appends `/1.0/sync/1.5`.
TOKENSERVER_PREFIX = "/token"
#: The tokenserver's `node`, and therefore the prefix of every `api_endpoint`
#: it hands out: Firefox appends `/1.5/<uid>` and then the storage path.
STORAGE_PREFIX = "/storage"


def create_app(
    config: Config, *, db: Database | None = None, signing_keys: SigningKeys | None = None
) -> FastAPI:
    """Build the application.

    `db` and `signing_keys` are injectable so tests can share one in-memory
    database and one RSA key across a whole session rather than paying for
    either per test. In production both come from the config's paths, and the
    signing key is read *now* — a missing key should stop the process, not
    surface as a 500 on the first sign-in.
    """
    keys = signing_keys or load_signing_keys(config.paths.signing_key, config.paths.retired_key)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.db = db if db is not None else open_database(config.paths.database)
        try:
            yield
        finally:
            if db is None:
                app.state.db.close()

    app = FastAPI(
        title="fxa-lite",
        version=__version__,
        lifespan=lifespan,
        # The reference exposes no OpenAPI UI on the API origin, and neither
        # /docs nor /redoc has anything to say to Firefox.
        docs_url=None,
        redoc_url=None,
    )
    app.state.config = config
    app.state.signing_keys = keys
    app.state.clients = Registry(config.clients)
    # The tokenserver and the storage tier share this; here they are the same
    # process, so it falls out of the signing key unless configured. See
    # `tokenlib.resolve_shared_secret`.
    app.state.tokenserver_secret = tokenlib.resolve_shared_secret(
        config.tokenserver_shared_secret, keys.private
    )
    # What is left of the customs server: see `throttle.py`. It is per-app
    # rather than global so that two apps in one test process — or one
    # `--reload` generation and the next — do not share a counter.
    app.state.throttle = FailureThrottle(
        limit=config.security.failed_login_limit,
        window=config.security.failed_login_window,
    )
    if db is not None:
        app.state.db = db

    app.include_router(auth.router(), prefix=API_PREFIX)
    app.include_router(oauth_routes.router, prefix=API_PREFIX)
    app.include_router(profile.router, prefix=PROFILE_PREFIX)
    app.include_router(tokenserver.router, prefix=TOKENSERVER_PREFIX)
    app.include_router(syncstorage.router, prefix=STORAGE_PREFIX)
    app.include_router(wellknown.router)
    app.include_router(content.router)
    # Added innermost-first: Starlette wraps each new middleware *around* the
    # ones already added, so the request meets `Trace`, then `SecurityHeaders`,
    # then `BodyLimit`, then a route.
    #
    # `BodyLimit` has to sit below `Trace` — an oversized body must be refused
    # before anything, tracing included, accumulates it — and below
    # `SecurityHeaders`, so its 413 is stamped like every other response.
    app.add_middleware(
        middleware.BodyLimit,
        storage_prefix=STORAGE_PREFIX,
        tokenserver_prefix=TOKENSERVER_PREFIX,
    )
    app.add_middleware(middleware.SecurityHeaders)
    # Outermost, so a request that never reaches a route is still described and
    # the status a handler actually produced is the one recorded. It renders
    # nothing unless the `fxa_lite` logger is at DEBUG.
    app.add_middleware(tracing.Trace)
    _add_defaults(app, config)
    _add_error_handlers(app)
    return app


# DIVERGENCE: root-belongs-to-the-content-server — `/` is the sign-in page
#   upstream: the auth server answers `/` with its version document and the
#     content server answers `/` with the sign-in page. They are two origins, so
#     both are true at once.
#   fxa-lite: one origin, so `/` is the page Firefox opens to sign in and the
#     version document lives only at `/__version__`.
#   why: `identity.fxaccounts.autoconfig.uri` points a browser at an origin, and
#     what it opens there has to be the page. Everything else in the layout is
#     ours to choose because discovery announces it; this one is forced.
#   cost: a tool that probes `/` for the auth server's version document finds
#     HTML. `/__version__`, `/__heartbeat__` and `/__lbheartbeat__` are where
#     upstream also serves them.
def _add_defaults(app: FastAPI, config: Config) -> None:
    """`lib/routes/defaults.js` — the operational endpoints, plus `/config`."""

    version = {
        "version": __version__,
        "commit": "",
        "source": "https://github.com/jaj/fxa-lite",
    }

    # No `/` alias for the version document: Firefox opens `/` to sign in, so
    # the content server owns it. Upstream can serve both because the auth
    # server and the content server are different origins.
    @app.get("/__version__")
    def version_handler() -> dict[str, Any]:
        return version

    @app.get("/__heartbeat__")
    def heartbeat(request: Request) -> dict[str, Any]:
        try:
            request.app.state.db.ping()
        except Exception as exc:  # noqa: BLE001 - any failure means "not serving"
            raise errors.service_unavailable() from exc
        return {}

    @app.get("/__lbheartbeat__")
    def lbheartbeat() -> dict[str, Any]:
        return {}

    @app.get("/config")
    def legacy_config() -> dict[str, Any]:
        """A legacy OAuth route the tokenserver still reads. Cheap to keep."""
        return {"contentUrl": config.public_url}


def _add_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(tokenserver.errors.TokenserverError)
    async def tokenserver_error_handler(
        request: Request, exc: tokenserver.errors.TokenserverError
    ) -> JSONResponse:
        """The tokenserver's envelope is not the accounts API's — see its `errors`."""
        return JSONResponse(exc.payload, status_code=exc.http_status)

    @app.exception_handler(syncstorage.errors.SyncStorageError)
    async def sync_storage_error_handler(
        request: Request, exc: syncstorage.errors.SyncStorageError
    ) -> Response:
        """Sync 1.5 answers with a bare integer, or with nothing at all.

        304 and 412 are answers, not failures: they carry `X-Last-Modified` and
        no body, because a body on a 304 is a protocol violation and a client
        that reads one gets a record it did not ask for.
        """
        if exc.status_code in (304, 412):
            response: Response = Response(status_code=exc.status_code, headers=exc.headers)
        else:
            response = JSONResponse(
                exc.payload, status_code=exc.status_code, headers=exc.headers
            )
        # Upstream stamps this on every response including errors, and a client
        # whose credential was just refused over clock skew learns the server's
        # time from the refusal itself.
        syncstorage.weave_timestamp(response)
        return response

    @app.exception_handler(errors.FxaError)
    async def fxa_error_handler(request: Request, exc: errors.FxaError) -> JSONResponse:
        return JSONResponse(exc.payload, status_code=exc.code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return await fxa_error_handler(request, _from_validation_error(request, exc))

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> Response:
        if request.url.path.startswith(f"{STORAGE_PREFIX}/"):
            # `render_404` upstream: a 404 below the storage prefix is still a
            # Sync response, and Sync's whole error vocabulary is one integer.
            # Handing it the accounts envelope would read as a JSON object
            # where the client expects a number.
            return await sync_storage_error_handler(
                request, syncstorage.errors.SyncStorageError(exc.status_code)
            )
        if request.url.path.startswith(f"{TOKENSERVER_PREFIX}/"):
            # A 404 below `/token` is still a tokenserver response. Firefox has
            # a separate parser for each shape and reads `status` out of this
            # one; handing it the accounts envelope here would look like a
            # success with no fields.
            return await tokenserver_error_handler(
                request,
                tokenserver.errors.unsupported("Unsupported application", "application"),
            )
        return await fxa_error_handler(request, _from_http_exception(exc))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return await fxa_error_handler(request, errors.unexpected_error())


def _from_validation_error(request: Request, exc: RequestValidationError) -> errors.FxaError:
    """Map pydantic's first complaint onto the right errno for the route it hit.

    Clients distinguish "you left something out" from "what you sent is wrong",
    and the reference's joi layer does too. `loc` for a body field looks like
    `("body", "authPW")`; the last element is the name worth reporting.

    The OAuth routes answer from a different errno table, where one value —
    `109`, invalid request parameter — covers both cases. Routing has already
    happened by the time validation fails, so the matched route's tags say which
    table to use.
    """
    first = exc.errors()[0] if exc.errors() else {}
    location = first.get("loc") or ()
    name = str(location[-1]) if location else None
    if "oauth" in _route_tags(request):
        return errors.oauth_invalid_request_parameter({"keys": [name] if name else []})
    if first.get("type") == "missing":
        return errors.missing_request_parameter(name)
    return errors.invalid_request_parameter(name)


def _route_tags(request: Request) -> tuple[str, ...]:
    route = request.scope.get("route")
    return tuple(getattr(route, "tags", ()) or ())


def _from_http_exception(exc: HTTPException) -> errors.FxaError:
    if exc.status_code == 404:
        return errors.FxaError(
            code=404,
            errno=errors.Errno.ENDPOINT_NOT_SUPPORTED,
            error="Not Found",
            message="Unknown endpoint",
        )
    if exc.status_code == 405:
        return errors.FxaError(
            code=405,
            errno=errors.Errno.ENDPOINT_NOT_SUPPORTED,
            error="Method Not Allowed",
            message="Method not allowed",
        )
    if exc.status_code == 413:
        return errors.request_body_too_large()
    return errors.FxaError(
        code=exc.status_code,
        errno=errors.Errno.UNEXPECTED_ERROR,
        error="Error",
        message=str(exc.detail),
    )
