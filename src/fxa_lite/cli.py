"""Command line entry point.

`keygen` makes the signing key, `account` provisions the handful of accounts
this server exists for, and `serve` runs the thing.  There is deliberately no
signup page: adding a user is an administrative act on the machine that holds
the database.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from . import __version__, accounts, tracing
from .config import LOG_LEVELS, Config, ConfigError, load
from .crypto import jose
from .db import Database, DatabaseError, open_database
from .errors import FxaError

DEFAULT_CONFIG = "fxa.toml"

#: Long enough that PBKDF2 is not the only thing standing between an attacker
#: and kB. The reference enforces 8; Sync keys deserve better than that.
MINIMUM_PASSWORD_LENGTH = 12


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ConfigError as exc:
        parser.exit(2, f"config error: {exc}\n")
    except DatabaseError as exc:
        parser.exit(2, f"database error: {exc}\n")
    except FxaError as exc:
        parser.exit(1, f"{exc.message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fxa-lite", description=__doc__)
    parser.add_argument("--version", action="version", version=f"fxa-lite {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser(
        "keygen",
        help="generate the RSA signing key used for OAuth access tokens and /v1/jwks",
    )
    _add_config_argument(keygen)
    keygen.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the private JWK here instead of the config's paths.signing_key",
    )
    keygen.add_argument(
        "-f", "--force", action="store_true", help="overwrite an existing key file"
    )
    keygen.set_defaults(handler=cmd_keygen)

    serve = sub.add_parser("serve", help="run the accounts, OAuth, profile and sync server")
    _add_config_argument(serve)
    serve.add_argument("--host", help="override [listen] host")
    serve.add_argument("--port", type=int, help="override [listen] port")
    serve.add_argument(
        "--reload", action="store_true", help="restart on source changes (development)"
    )
    serve.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        help="override [log] level; `debug` traces request and response bodies "
        "(credentials are redacted, but the output is still not for sharing)",
    )
    serve.set_defaults(handler=cmd_serve)

    account = sub.add_parser("account", help="provision the accounts allowed to sign in")
    account_sub = account.add_subparsers(dest="account_command", required=True)

    account_add = account_sub.add_parser("add", help="create an account")
    _add_config_argument(account_add)
    account_add.add_argument("email")
    account_add.add_argument(
        "--password",
        help="read the password from the command line instead of prompting "
        "(it will be visible in your shell history and process list)",
    )
    account_add.set_defaults(handler=cmd_account_add)

    account_list = account_sub.add_parser("list", help="list accounts")
    _add_config_argument(account_list)
    account_list.set_defaults(handler=cmd_account_list)

    account_remove = account_sub.add_parser(
        "remove", help="delete an account, its sessions and its devices"
    )
    _add_config_argument(account_remove)
    account_remove.add_argument("email")
    account_remove.add_argument(
        "-f", "--force", action="store_true", help="skip the confirmation prompt"
    )
    account_remove.set_defaults(handler=cmd_account_remove)

    return parser


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(os.environ.get("FXA_LITE_CONFIG", DEFAULT_CONFIG)),
        help=f"path to the TOML config file (default: {DEFAULT_CONFIG})",
    )


def cmd_keygen(args: argparse.Namespace) -> int:
    destination: Path | None = args.output
    if destination is None:
        config: Config = load(args.config)
        destination = config.paths.signing_key

    if destination.exists() and not args.force:
        print(
            f"{destination} already exists; pass --force to replace it "
            f"(every token signed by the old key stops verifying)",
            file=sys.stderr,
        )
        return 1

    key = jose.generate_signing_key()
    jwk = jose.private_key_to_jwk(key)
    write_private_jwk(destination, jwk)
    print(f"signing key written to {destination} (kid {jwk['kid']})")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    config: Config = load(args.config)
    level = args.log_level or config.log.level
    tracing.configure(level)
    if not config.paths.signing_key.exists():
        print(
            f"no signing key at {config.paths.signing_key}; run `fxa-lite keygen` first",
            file=sys.stderr,
        )
        return 1
    # Opening it here rather than in the lifespan turns a broken database into
    # an error message instead of a stack trace on the first request.
    open_database(config.paths.database).close()

    host = args.host or config.listen.host
    port = args.port or config.listen.port
    print(f"fxa-lite {__version__} serving {config.public_url} on {host}:{port}")
    if level == "debug":
        print(
            "tracing request and response bodies; credentials are redacted, "
            "but treat the output as sensitive",
            file=sys.stderr,
        )
    uvicorn.run(create_app(config), host=host, port=port, reload=args.reload)
    return 0


def cmd_account_add(args: argparse.Namespace) -> int:
    config: Config = load(args.config)
    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Password (again): "):
            print("passwords do not match", file=sys.stderr)
            return 1
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        print(
            f"password must be at least {MINIMUM_PASSWORD_LENGTH} characters: it is the "
            f"only thing protecting the Sync encryption key",
            file=sys.stderr,
        )
        return 1

    with _database(config) as db:
        account = accounts.provision_with_password(db, email=args.email, password=password)
    print(f"created {account.email} (uid {account.uid})")
    return 0


def cmd_account_list(args: argparse.Namespace) -> int:
    config: Config = load(args.config)
    with _database(config) as db:
        rows = db.accounts()
        if not rows:
            print("no accounts; add one with `fxa-lite account add <email>`")
            return 0
        width = max(len(account.email) for account in rows)
        for account in rows:
            created = _timestamp(account.created_at)
            sessions = len(db.session_tokens(account.uid))
            devices = len(db.devices(account.uid))
            print(
                f"{account.email:<{width}}  {account.uid}  created {created}  "
                f"{sessions} session(s), {devices} device(s)"
            )
    return 0


def cmd_account_remove(args: argparse.Namespace) -> int:
    config: Config = load(args.config)
    with _database(config) as db:
        account = db.account_by_email(args.email)
        if account is None:
            print(f"no such account: {args.email}", file=sys.stderr)
            return 1
        if not args.force:
            answer = input(
                f"delete {account.email} ({account.uid}) and all its sessions? [y/N] "
            )
            if answer.strip().lower() not in ("y", "yes"):
                print("cancelled")
                return 1
        db.delete_account(account.uid)
    print(f"deleted {account.email}")
    return 0


@contextmanager
def _database(config: Config) -> Iterator[Database]:
    db = open_database(config.paths.database)
    try:
        yield db
    finally:
        db.close()


def _timestamp(milliseconds: int) -> str:
    moment = datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%SZ")


def write_private_jwk(destination: Path, jwk: dict[str, object]) -> None:
    """Write a private JWK owner-readable only, replacing any existing file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.name}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(jwk, fh, indent=2)
            fh.write("\n")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    temporary.replace(destination)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
