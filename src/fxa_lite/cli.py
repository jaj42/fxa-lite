"""Command line entry point.

Phase 0 ships `keygen`; `serve` and `account …` arrive with the phases that
have something to serve and somewhere to store accounts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, load
from .crypto import jose

DEFAULT_CONFIG = "fxa.toml"


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ConfigError as exc:
        parser.exit(2, f"config error: {exc}\n")


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
