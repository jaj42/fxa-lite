"""FastAPI assembly: routers, error rendering, lifespan.

One app, one origin.  The accounts API mounts at `/v1` — the same prefix the
reference auth server uses, because `/.well-known/fxa-client-configuration`
(phase 3) advertises it and Firefox appends the rest of the path itself.

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

from . import __version__, auth, errors
from .config import Config
from .db import Database, open_database

#: The prefix the reference auth server serves its API from.
API_PREFIX = "/v1"


def create_app(config: Config, *, db: Database | None = None) -> FastAPI:
    """Build the application. Pass `db` to reuse an already-open database (tests)."""

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
    if db is not None:
        app.state.db = db

    app.include_router(auth.router(), prefix=API_PREFIX)
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
        return await fxa_error_handler(request, _from_validation_error(exc))

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return await fxa_error_handler(request, _from_http_exception(exc))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return await fxa_error_handler(request, errors.unexpected_error())


def _from_validation_error(exc: RequestValidationError) -> errors.FxaError:
    """Map pydantic's first complaint onto errno 107/108.

    Clients distinguish "you left something out" from "what you sent is wrong",
    and the reference's joi layer does too. `loc` for a body field looks like
    `("body", "authPW")`; the last element is the name worth reporting.
    """
    first = exc.errors()[0] if exc.errors() else {}
    location = first.get("loc") or ()
    name = str(location[-1]) if location else None
    if first.get("type") == "missing":
        return errors.missing_request_parameter(name)
    return errors.invalid_request_parameter(name)


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
