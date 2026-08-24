"""FastAPI assembly: routers, error rendering, lifespan.

One app, one origin.  The accounts and OAuth APIs mount at `/v1` — the prefix
the reference auth server uses, and the one it serves OAuth from too — the
profile server at `/profile/v1`, and the discovery documents at the root.
`/.well-known/fxa-client-configuration` tells Firefox where each of those is,
so the layout is ours to choose; see `wellknown.py`.

The error handlers matter as much as the routes.  A client reads `errno`, not
the HTTP status, so an unhandled exception that escapes as FastAPI's default
`{"detail": ...}` is not "a 500 with a different body" — it is a response the
client cannot interpret at all.  Everything is funnelled through
`errors.FxaError`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from . import __version__, auth, errors, profile, wellknown
from .config import Config
from .db import Database, open_database
from .oauth import routes as oauth_routes
from .oauth.clients import Registry
from .oauth.keys import SigningKeys
from .oauth.keys import load as load_signing_keys

#: The prefix the reference auth server serves its API from. The OAuth routes
#: share it: upstream they are one process behind one prefix, and Firefox's
#: `oauth_server_base_url` and `auth_server_base_url` may well be the same host.
API_PREFIX = "/v1"
#: `fxa-profile-server`'s own prefix, below a mount of our choosing.
PROFILE_PREFIX = "/profile/v1"


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
    if db is not None:
        app.state.db = db

    app.include_router(auth.router(), prefix=API_PREFIX)
    app.include_router(oauth_routes.router, prefix=API_PREFIX)
    app.include_router(profile.router, prefix=PROFILE_PREFIX)
    app.include_router(wellknown.router)
    _add_defaults(app, config)
    _add_error_handlers(app)
    return app


def _add_defaults(app: FastAPI, config: Config) -> None:
    """`lib/routes/defaults.js` — the operational endpoints, plus `/config`."""

    version = {
        "version": __version__,
        "commit": "",
        "source": "https://github.com/jaj/fxa-lite",
    }

    @app.get("/")
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
    @app.exception_handler(errors.FxaError)
    async def fxa_error_handler(request: Request, exc: errors.FxaError) -> JSONResponse:
        return JSONResponse(exc.payload, status_code=exc.code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return await fxa_error_handler(request, _from_validation_error(request, exc))

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
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
