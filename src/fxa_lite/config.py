# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""TOML configuration -> frozen dataclasses.

Everything fxa-lite needs to run lives in one file; see `fxa.example.toml`.
Relative paths are resolved against the directory holding the config file, so a
config plus its SQLite database and signing key can be moved as a unit.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .oauth.clients import Client, ClientError
from .oauth.clients import build as build_clients

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000

# 6 hours: at or below fxa-shared's SHORT_ACCESS_TTL_TOKEN_IN_MS, which is what
# lets an access token be a self-contained JWT with no server-side record.
DEFAULT_ACCESS_TOKEN_TTL = 6 * 3600
# `oauthServer.expiration.code` upstream.
DEFAULT_CODE_TTL = 15 * 60
# syncstorage-rs `token_duration` default.
DEFAULT_TOKENSERVER_TTL = 3600

#: What `[log] level` accepts. `debug` additionally traces request and response
#: bodies — see `tracing.py` for what that does and does not write down.
LOG_LEVELS = ("debug", "info", "warning", "error")
DEFAULT_LOG_LEVEL = "info"

#: Failed password checks a single account tolerates inside the window below
#: before `/account/login` refuses to run scrypt again. Ten is generous for a
#: person typing and worthless to someone guessing: at this rate a six-word
#: passphrase outlasts the sun. Only *failures* are counted, so a client that
#: knows the password is never locked out by one that does not.
DEFAULT_FAILED_LOGIN_LIMIT = 10
#: And how long they are remembered. Short enough that a fat-fingered morning
#: is over by the time coffee is, long enough that guessing gains nothing.
DEFAULT_FAILED_LOGIN_WINDOW = 300


class ConfigError(ValueError):
    """Raised for a malformed or incomplete config file."""


@dataclass(frozen=True, slots=True)
class ListenConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT


@dataclass(frozen=True, slots=True)
class PathsConfig:
    database: Path = Path("fxa.sqlite")
    signing_key: Path = Path("signing-key.json")
    #: Public JWK of a retired signing key, still served from /v1/jwks so that
    #: tokens signed before a rotation keep verifying.
    retired_key: Path | None = None


@dataclass(frozen=True, slots=True)
class LogConfig:
    level: str = DEFAULT_LOG_LEVEL

    @property
    def traces_bodies(self) -> bool:
        return self.level == "debug"


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """The two switches an operator may reasonably want on a public origin.

    Both default to the safe answer, which is why they are here rather than
    hard-coded: a household server is reachable from the internet the moment a
    port is forwarded, and the defaults have to survive that.
    """

    #: Whether `POST /v1/account/create` provisions accounts for anyone who
    #: asks. Off: `fxa-lite account add` is the signup funnel, and an open
    #: endpoint here hands an unauthenticated stranger one scrypt per request.
    open_registration: bool = False
    #: Consecutive failed password checks per account before `/account/login`
    #: answers 429 instead of stretching a password. 0 disables the throttle.
    failed_login_limit: int = DEFAULT_FAILED_LOGIN_LIMIT
    #: Seconds a failure is remembered for, and what a throttled client is told
    #: to wait.
    failed_login_window: int = DEFAULT_FAILED_LOGIN_WINDOW


@dataclass(frozen=True, slots=True)
class TtlConfig:
    access_token: int = DEFAULT_ACCESS_TOKEN_TTL
    authorization_code: int = DEFAULT_CODE_TTL
    tokenserver_token: int = DEFAULT_TOKENSERVER_TTL


@dataclass(frozen=True, slots=True)
class Config:
    #: Origin Firefox is pointed at, without a trailing slash.
    public_url: str
    listen: ListenConfig = field(default_factory=ListenConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    ttl: TtlConfig = field(default_factory=TtlConfig)
    log: LogConfig = field(default_factory=LogConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    #: HMAC secret shared between the tokenserver and sync storage tiers.
    tokenserver_shared_secret: str | None = None
    #: OAuth clients: the three browsers, plus anything `[[clients]]` adds.
    clients: tuple[Client, ...] = ()
    #: Config file this was loaded from, if any.
    source: Path | None = None

    def url(self, path: str = "") -> str:
        """Absolute URL for a path below `public_url`."""
        if not path:
            return self.public_url
        return f"{self.public_url}/{path.lstrip('/')}"


def load(path: str | Path) -> Config:
    """Read and validate a TOML config file."""
    path = Path(path)
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return from_dict(data, base=path.parent, source=path)


def from_dict(
    data: dict[str, Any], *, base: Path | None = None, source: Path | None = None
) -> Config:
    base = Path(base) if base is not None else Path.cwd()
    _reject_unknown(
        data,
        {
            "public_url",
            "tokenserver_shared_secret",
            "clients",
            "listen",
            "paths",
            "ttl",
            "log",
            "security",
        },
        "",
    )

    public_url = _public_url(_require(data, "public_url", str, ""))
    listen_raw = _section(data, "listen")
    paths_raw = _section(data, "paths")
    ttl_raw = _section(data, "ttl")
    log_raw = _section(data, "log")
    security_raw = _section(data, "security")

    _reject_unknown(listen_raw, {"host", "port"}, "listen")
    _reject_unknown(log_raw, {"level"}, "log")
    _reject_unknown(paths_raw, {"database", "signing_key", "retired_key"}, "paths")
    _reject_unknown(ttl_raw, {"access_token", "authorization_code", "tokenserver_token"}, "ttl")
    _reject_unknown(
        security_raw,
        {"open_registration", "failed_login_limit", "failed_login_window"},
        "security",
    )

    listen = ListenConfig(
        host=_get(listen_raw, "host", str, "listen", DEFAULT_HOST),
        port=_port(_get(listen_raw, "port", int, "listen", DEFAULT_PORT)),
    )
    paths = PathsConfig(
        database=_path(_get(paths_raw, "database", str, "paths", "fxa.sqlite"), base),
        signing_key=_path(_get(paths_raw, "signing_key", str, "paths", "signing-key.json"), base),
        retired_key=(
            _path(_get(paths_raw, "retired_key", str, "paths", ""), base)
            if paths_raw.get("retired_key") is not None
            else None
        ),
    )
    ttl = TtlConfig(
        access_token=_seconds(ttl_raw, "access_token", DEFAULT_ACCESS_TOKEN_TTL),
        authorization_code=_seconds(ttl_raw, "authorization_code", DEFAULT_CODE_TTL),
        tokenserver_token=_seconds(ttl_raw, "tokenserver_token", DEFAULT_TOKENSERVER_TTL),
    )
    log = LogConfig(level=_log_level(_get(log_raw, "level", str, "log", DEFAULT_LOG_LEVEL)))
    security = SecurityConfig(
        open_registration=_get(security_raw, "open_registration", bool, "security", False),
        failed_login_limit=_count(security_raw, "failed_login_limit", DEFAULT_FAILED_LOGIN_LIMIT),
        failed_login_window=_seconds(
            security_raw, "failed_login_window", DEFAULT_FAILED_LOGIN_WINDOW, where="security"
        ),
    )

    clients_raw = data.get("clients", [])
    if not isinstance(clients_raw, list) or not all(
        isinstance(entry, dict) for entry in clients_raw
    ):
        raise ConfigError("clients must be an array of tables ([[clients]])")
    try:
        clients = build_clients(public_url, clients_raw)
    except (ClientError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc

    secret = data.get("tokenserver_shared_secret")
    if secret is not None and (not isinstance(secret, str) or not secret):
        raise ConfigError("tokenserver_shared_secret must be a non-empty string")

    return Config(
        public_url=public_url,
        listen=listen,
        paths=paths,
        ttl=ttl,
        log=log,
        security=security,
        tokenserver_shared_secret=secret,
        clients=clients,
        source=source,
    )


def _log_level(value: str) -> str:
    level = value.lower()
    if level not in LOG_LEVELS:
        raise ConfigError(f"log.level must be one of {', '.join(LOG_LEVELS)}, got {value!r}")
    return level


def _public_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError(f"public_url must be an absolute http(s) URL, got {value!r}")
    if parts.query or parts.fragment:
        raise ConfigError("public_url must not carry a query string or fragment")
    return value.rstrip("/")


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def _reject_unknown(data: dict[str, Any], known: set[str], where: str) -> None:
    unknown = sorted(set(data) - known)
    if unknown:
        location = f"[{where}]" if where else "config"
        raise ConfigError(f"unknown key(s) in {location}: {', '.join(unknown)}")


def _require(data: dict[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in data:
        raise ConfigError(f"missing required key {_label(key, where)}")
    return _get(data, key, kind, where, None)


def _get(data: dict[str, Any], key: str, kind: type, where: str, default: Any) -> Any:
    if key not in data:
        return default
    value = data[key]
    # bool is an int subclass; never let `port = true` through as an int.
    if isinstance(value, bool) and kind is not bool:
        raise ConfigError(f"{_label(key, where)} must be {kind.__name__}")
    if not isinstance(value, kind):
        raise ConfigError(f"{_label(key, where)} must be {kind.__name__}")
    return value


def _label(key: str, where: str) -> str:
    return f"{where}.{key}" if where else key


def _port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise ConfigError(f"listen.port out of range: {value}")
    return value


def _seconds(data: dict[str, Any], key: str, default: int, *, where: str = "ttl") -> int:
    value = _get(data, key, int, where, default)
    if value <= 0:
        raise ConfigError(f"{where}.{key} must be a positive number of seconds")
    return value


def _count(data: dict[str, Any], key: str, default: int) -> int:
    """A non-negative limit; 0 is a meaningful value — "no throttle at all"."""
    value = _get(data, key, int, "security", default)
    if value < 0:
        raise ConfigError(f"security.{key} must not be negative")
    return value


def _path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base / path).resolve()
