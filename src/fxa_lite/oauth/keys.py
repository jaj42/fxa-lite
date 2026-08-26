# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The signing key, and the JWKS built from it.

`lib/oauth/keys.ts`.  One RSA key signs every access token; `/v1/jwks` publishes
its public half so the Sync tokenserver (phase 5) can verify a token without
asking us anything.  A retired key's public JWK can be published alongside it,
so rotating the signing key does not invalidate tokens signed a minute earlier.

Loading happens once, at startup, on purpose: a missing or malformed key should
stop the process, not surface as a 500 on the first sign-in.
"""

from __future__ import annotations

import json
import logging
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from ..crypto import jose

logger = logging.getLogger(__name__)


class SigningKeyError(RuntimeError):
    """Raised when the signing key is missing or cannot be parsed."""


@dataclass(frozen=True, slots=True)
class SigningKeys:
    """The key we sign with, plus every key we still accept signatures from."""

    private: rsa.RSAPrivateKey
    kid: str
    #: kid -> public key, for verifying our own access tokens on `/v1/verify`.
    verifiers: dict[str, rsa.RSAPublicKey]
    #: The exact document `/v1/jwks` serves.
    jwks: dict[str, Any]

    def sign(self, claims: dict[str, Any], *, typ: str = "JWT") -> str:
        return jose.sign_jwt(claims, self.private, kid=self.kid, typ=typ)

    def verify(self, token: str, *, now: int | None = None) -> dict[str, Any]:
        """Verify signature and expiry. Audience, issuer and scope are the caller's."""
        return jose.verify_jwt(token, self.verifiers, now=now)


def load(signing_key: Path, retired_key: Path | None = None) -> SigningKeys:
    """Read the private signing JWK, and optionally a retired public one."""
    private_jwk = _read_jwk(signing_key, "signing key")
    _warn_if_readable(signing_key)
    try:
        private = jose.jwk_to_private_key(private_jwk)
    except ValueError as exc:
        raise SigningKeyError(f"{signing_key} is not a usable private JWK: {exc}") from exc
    kid = private_jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        raise SigningKeyError(f"{signing_key} has no kid; regenerate it with `fxa-lite keygen`")

    public = jose.public_jwk(private_jwk)
    keys = [public]
    verifiers = {kid: private.public_key()}

    if retired_key is not None:
        retired_jwk = jose.public_jwk(_read_jwk(retired_key, "retired key"))
        retired_kid = retired_jwk["kid"]
        if retired_kid == kid:
            raise SigningKeyError(
                f"{retired_key} has the same kid as the active key ({kid}); "
                f"a retired key must be a different key"
            )
        keys.append(retired_jwk)
        verifiers[retired_kid] = jose.jwk_to_public_key(retired_jwk)

    return SigningKeys(private=private, kid=kid, verifiers=verifiers, jwks={"keys": keys})


def _warn_if_readable(path: Path) -> None:
    """Say so if the private key is group- or world-readable.

    `keygen` writes it through `os.open(..., 0o600)` and nothing here ever
    widens it — but a key restored from a backup, copied into a container image
    or checked out of somebody's dotfiles repo arrives with whatever mode it
    was given. This is not narrowed automatically the way the database is: the
    database is a file fxa-lite creates and owns, and the signing key may be a
    mount, a secret handed in by an orchestrator, or a file deliberately shared
    with a second process. Saying so and starting is the honest answer.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - it was read a moment ago
        return
    if mode & 0o077:
        logger.warning(
            "%s is mode %o: the OAuth signing key should be readable only by "
            "the user fxa-lite runs as (chmod 600)",
            path,
            mode,
        )


def _read_jwk(path: Path, what: str) -> dict[str, Any]:
    try:
        raw = path.read_text()
    except OSError as exc:
        raise SigningKeyError(f"cannot read {what} {path}: {exc}") from exc
    try:
        jwk = json.loads(raw)
    except ValueError as exc:
        raise SigningKeyError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(jwk, dict) or "kid" not in jwk:
        raise SigningKeyError(f"{path} is not a JWK")
    return jwk
