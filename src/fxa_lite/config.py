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

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000

# 6 hours: at or below fxa-shared's SHORT_ACCESS_TTL_TOKEN_IN_MS, which is what
# lets an access token be a self-contained JWT with no server-side record.
DEFAULT_ACCESS_TOKEN_TTL = 6 * 3600
# `oauthServer.expiration.code` upstream.
DEFAULT_CODE_TTL = 15 * 60
# syncstorage-rs `token_duration` default.
DEFAULT_TOKENSERVER_TTL = 3600


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
    #: HMAC secret shared between the tokenserver and sync storage tiers.
    tokenserver_shared_secret: str | None = None
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
    _reject_unknown(data, {"public_url", "tokenserver_shared_secret", "listen", "paths", "ttl"}, "")

    public_url = _public_url(_require(data, "public_url", str, ""))
    listen_raw = _section(data, "listen")
    paths_raw = _section(data, "paths")
    ttl_raw = _section(data, "ttl")

    _reject_unknown(listen_raw, {"host", "port"}, "listen")
    _reject_unknown(paths_raw, {"database", "signing_key", "retired_key"}, "paths")
    _reject_unknown(ttl_raw, {"access_token", "authorization_code", "tokenserver_token"}, "ttl")

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
    secret = data.get("tokenserver_shared_secret")
    if secret is not None and (not isinstance(secret, str) or not secret):
        raise ConfigError("tokenserver_shared_secret must be a non-empty string")

    return Config(
        public_url=public_url,
        listen=listen,
        paths=paths,
        ttl=ttl,
        tokenserver_shared_secret=secret,
        source=source,
    )


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


def _seconds(data: dict[str, Any], key: str, default: int) -> int:
    value = _get(data, key, int, "ttl", default)
    if value <= 0:
        raise ConfigError(f"ttl.{key} must be a positive number of seconds")
    return value


def _path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base / path).resolve()
