"""The Sync tokenserver: an OAuth access token in, a storage credential out.

`syncstorage-rs/syncserver/src/tokenserver/{extractors,handlers}.rs`.

Firefox reaches this with `Authorization: Bearer <access token>` and an
`X-KeyID` header of `<keysChangedAt>-<base64url(sha256(kB)[:16])>` — the
fingerprint of the Sync key it just derived.  The reply names a numeric uid, a
storage URL, and a HAWK credential pair for signing requests against it.

Upstream this is a separate deployment that verifies the token by calling FxA's
`/v1/verify` (or checking it against a cached JWKS) and then allocates a
storage node from a pool.  Here the signing key is in memory and there is one
node — ourselves — so both steps collapse.  What does *not* collapse is the
consistency checking around `generation`, `keysChangedAt` and the client state:
those rules are the only thing standing between a stale credential and a client
silently writing records nobody can decrypt, and they are ported verbatim.

The rules, from `TokenserverRequest::validate`:

* `generation` rises on any authentication change, `keysChangedAt` on any key
  change, and a key change is an authentication change — so
  `keysChangedAt <= generation` always;
* neither may ever move backwards;
* a client state, once retired, must never be accepted again;
* a *new* client state must arrive with a rise in both timestamps.

A new client state that passes those checks is a key rotation: the account gets
a brand new Sync uid, and the old one's storage is left behind rather than
handed over.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Request, Response

from ..crypto import jose
from ..db import Database, SyncUser
from ..oauth.clients import OLDSYNC_SCOPE
from ..oauth.scopes import ScopeSet
from . import errors, tokenlib

router = APIRouter(tags=["tokenserver"])

#: The one application/version pair fxa-lite serves.
APPLICATION = "sync"
VERSION = "1.5"

#: `CLIENT_STATE_REGEX` — what an `X-Client-State` header may contain.
CLIENT_STATE_RE = re.compile(r"^[a-zA-Z0-9._-]{1,32}$")

#: Unpadded base64url, matched by hand because `base64.urlsafe_b64decode`
#: silently *discards* characters outside the alphabet rather than complaining.
#: Upstream decodes with `URL_SAFE_NO_PAD`, which rejects them — and rejects a
#: stray `=` too, so neither is allowed here.
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

#: What the response calls the storage backend. Upstream's enum is
#: mysql/spanner/postgres; ours is none of those, and no client reads the field
#: — Firefox ignores everything here but `id`, `key`, `uid` and `api_endpoint`.
NODE_TYPE = "sqlite"


@dataclass(frozen=True, slots=True)
class AuthData:
    """What the request claims about the account, from the token and the headers."""

    fxa_uid: str
    client_state: str
    #: `None` rather than 0 throughout: upstream folds zero into null on the way
    #: in, and the difference between "never reported" and "reported zero" is
    #: what several of the checks below turn on.
    generation: int | None
    keys_changed_at: int | None


@router.get("/1.0/{application}/{version}")
def token(application: str, version: str, request: Request, response: Response) -> dict[str, Any]:
    """Allocate (or look up) this account's Sync uid and mint its storage credential."""
    if application != APPLICATION:
        # Upstream names only "application" here, not the value it was given,
        # and the old Python tokenserver did the same. Kept for parity.
        raise errors.unsupported("Unsupported application", "application")
    if version != VERSION:
        raise errors.unsupported("Unsupported application version", version)

    config = request.app.state.config
    db: Database = request.app.state.db
    secret: str = request.app.state.tokenserver_secret

    auth = _auth_data(request)
    now_ms = int(time.time() * 1000)

    user, retired_client_states = _current_user(db, auth, now_ms)
    _validate(auth, user, retired_client_states)
    uid, generation, keys_changed_at = _apply(db, auth, user, now_ms)

    node = config.url("/storage")
    duration = _duration(request, config.ttl.tokenserver_token)
    hashed_fxa_uid = tokenlib.metrics_hash(auth.fxa_uid, secret)
    token_id, key = tokenlib.make_token(
        {
            "node": node,
            # `keysChangedAt` is what Sync keys are actually versioned by;
            # `generation` is the fallback for a client too old to report one.
            "fxa_kid": _fxa_kid(
                keys_changed_at if keys_changed_at is not None else generation, auth.client_state
            ),
            "fxa_uid": auth.fxa_uid,
            "hashed_device_id": tokenlib.hashed_device_id(hashed_fxa_uid, secret),
            "hashed_fxa_uid": hashed_fxa_uid,
            "expires": now_ms // 1000 + duration,
            "uid": uid,
            # Neither the Python nor the Rust tokenserver, but the field is
            # non-optional in the storage tier's payload struct.
            "tokenserver_origin": "python",
        },
        secret,
    )

    response.headers["X-Timestamp"] = str(now_ms // 1000)
    # Set by cornice on the original Python tokenserver; kept because a client
    # sniffing this response as HTML would be a bad day for someone.
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {
        "id": token_id,
        "key": key,
        "uid": uid,
        "api_endpoint": f"{node}/{VERSION}/{uid}",
        "duration": duration,
        "hashed_fxa_uid": hashed_fxa_uid,
        "hashalg": "sha256",
        "node_type": NODE_TYPE,
    }


# --------------------------------------------------------------------------
# Reading the request.
# --------------------------------------------------------------------------


def _auth_data(request: Request) -> AuthData:
    claims = _verified_access_token(request)
    key_id = _key_id(request)
    return AuthData(
        fxa_uid=claims["sub"],
        client_state=key_id[1],
        generation=_none_if_zero(claims.get("fxa-generation")),
        keys_changed_at=_none_if_zero(key_id[0]),
    )


# DIVERGENCE: tokenserver-audience-checked — `aud` is verified here
#   upstream: skips the check; its own comment says the ecosystem does not
#     request the right audience, so enforcing it would reject valid tokens.
#   fxa-lite: requires `aud` to be this deployment's own tokenserver URL.
#   why: `oauth/grant.py` is the only thing that mints that audience and mints
#     it only for the oldsync scope, so the check holds for every token that can
#     exist here. It is what stops a token issued to some other relier being
#     spent for Sync.
#   cost: nothing a client can trip. It does bind the tokenserver to
#     `public_url`: move the origin and outstanding access tokens stop being
#     spendable here, for at most `ttl.access_token`.
def _verified_access_token(request: Request) -> dict[str, Any]:
    """Verify the access token against our own signing key.

    Upstream fetches `/v1/jwks` over HTTP and caches it; the key is in this
    process, so there is nothing to fetch.  Every failure answers the same
    `invalid-credentials`, which is upstream's choice too: they are all the one
    instruction to the client, "get a new token".

    fxa-lite checks `aud`, which upstream deliberately skips — its comment says
    the ecosystem does not request the right audience, so the check would fail
    on valid tokens.  Ours mints that audience itself (`grant.py`), so the check
    holds, and it is what stops a token issued for some other relier from being
    spent here.
    """
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if not token or scheme.lower() != "bearer":
        raise errors.invalid_credentials("Unauthorized")

    try:
        claims = request.app.state.signing_keys.verify(token.strip())
    except jose.JWTError as exc:
        raise errors.invalid_credentials("Unauthorized") from exc
    if jose.decode_jwt_header(token.strip()).get("typ") != "at+JWT":
        # An id token, or anything else we happen to have signed, is not this.
        raise errors.invalid_credentials("Unauthorized")

    config = request.app.state.config
    if claims.get("iss") != config.public_url or claims.get("aud") != config.url("/token"):
        raise errors.invalid_credentials("Unauthorized")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise errors.invalid_credentials("Unauthorized")
    if not ScopeSet.from_string(claims.get("scope", "")).contains(OLDSYNC_SCOPE):
        raise errors.invalid_credentials("Unauthorized")
    return claims


def _key_id(request: Request) -> tuple[int, str]:
    """`X-KeyID: <keysChangedAt>-<base64url client state>` -> `(keysChangedAt, hex)`.

    The client state travels base64url-encoded here and hex-encoded in
    `X-Client-State`; when both are present they must agree, since they are two
    spellings of the same 16 bytes.
    """
    raw = request.headers.get("x-keyid")
    if raw is None:
        raise errors.invalid_key_id("Missing X-KeyID header")
    if not raw.isascii():
        raise errors.invalid_key_id("Invalid X-KeyID header")

    timestamp, separator, encoded = raw.partition("-")
    if not separator:
        raise errors.invalid_credentials("Unauthorized")
    try:
        keys_changed_at = int(timestamp)
    except ValueError as exc:
        raise errors.invalid_credentials("Unauthorized") from exc
    if not B64URL_RE.match(encoded):
        raise errors.invalid_credentials("Unauthorized")
    try:
        client_state = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).hex()
    except (ValueError, binascii.Error) as exc:
        raise errors.invalid_credentials("Unauthorized") from exc

    declared = _x_client_state(request)
    if declared is not None and declared != client_state:
        raise errors.invalid_client_state("Client state mismatch in X-Client-State header")
    return keys_changed_at, client_state


def _x_client_state(request: Request) -> str | None:
    value = request.headers.get("x-client-state")
    if value is None:
        return None
    if not CLIENT_STATE_RE.match(value):
        raise errors.bad_client_state_header()
    return value


def _duration(request: Request, default: int) -> int:
    """`?duration=` may shorten a token but never lengthen it.

    A malformed value is ignored rather than rejected — upstream is explicit
    that a bad `duration` must never fail a request, since the client can
    always be served the default instead.
    """
    raw = request.query_params.get("duration")
    if raw is None:
        return default
    try:
        requested = int(raw)
    except ValueError:
        return default
    return requested if 0 < requested <= default else default


def _none_if_zero(value: Any) -> int | None:
    """Upstream's `convert_zero_to_none`: the Python tokenserver conflated the two."""
    if isinstance(value, int) and not isinstance(value, bool) and value != 0:
        return value
    return None


def _fxa_kid(timestamp: int, client_state: str) -> str:
    """`<13-digit zero-padded ms>-<base64url client state>`, as storage expects it."""
    encoded = base64.urlsafe_b64encode(bytes.fromhex(client_state)).rstrip(b"=").decode("ascii")
    return f"{timestamp:013d}-{encoded}"


# --------------------------------------------------------------------------
# The user record.
# --------------------------------------------------------------------------


def _current_user(db: Database, auth: AuthData, now_ms: int) -> tuple[SyncUser, set[str]]:
    """The account's current Sync user, creating it on first sight.

    Also returns the client states this account has already retired, which the
    validation below refuses to accept a second time — coming back to an old
    key is how a client ends up writing records under a key the server has
    already told everyone else to stop using.
    """
    rows = db.sync_users(auth.fxa_uid)
    if not rows:
        if db.account(auth.fxa_uid) is None:
            # An access token outlives the account it names by up to its TTL.
            # Saying so as `invalid-credentials` sends the client back to sign
            # in, which is the only thing that could help it.
            raise errors.invalid_credentials("Unauthorized")
        user = db.create_sync_user(
            fxa_uid=auth.fxa_uid,
            client_state=auth.client_state,
            generation=auth.generation or 0,
            keys_changed_at=auth.keys_changed_at,
            created_at=now_ms,
        )
        return user, set()

    current, history = rows[0], rows[1:]
    # Rows can be left unreplaced by a crash between the insert and the update;
    # squaring that away here keeps the invariant "exactly one live row" true
    # for the storage tier, which reads it without this reconciliation.
    for old in history:
        if old.replaced_at is None:
            db.replace_sync_user(old.uid, current.created_at)
    retired = {old.client_state for old in history if old.client_state != current.client_state}
    return current, retired


def _validate(auth: AuthData, user: SyncUser, retired_client_states: set[str]) -> None:
    """`TokenserverRequest::validate`, in the order it runs.

    Every comparison between a claimed value and a stored one is skipped when
    either side is absent — upstream's `opt_cmp!` macro, which yields `false`
    for a missing operand. The asymmetry is deliberate: a client that has never
    reported a `generation` must not be locked out by one, but a client that
    has reported one may not stop.
    """
    changed_state = auth.client_state != user.client_state

    # A key change is an authentication change, so a rise in keysChangedAt that
    # outruns the reported generation means the two came from different servers.
    if _gt(auth.keys_changed_at, user.keys_changed_at) and _lt(
        auth.generation, auth.keys_changed_at
    ):
        raise errors.invalid_keys_changed_at()

    if user.client_state and not auth.client_state:
        raise errors.invalid_client_state("Unacceptable client-state value empty string")
    if auth.client_state in retired_client_states:
        raise errors.invalid_client_state("Unacceptable client-state value stale value")
    if changed_state and _le(auth.generation, user.generation):
        raise errors.invalid_client_state(
            "Unacceptable client-state value new value with no generation change"
        )
    if changed_state and _le(auth.keys_changed_at, user.keys_changed_at):
        raise errors.invalid_client_state(
            "Unacceptable client-state value new value with no keys_changed_at change"
        )
    if _gt(user.generation, auth.generation):
        raise errors.invalid_generation()
    if _gt(user.keys_changed_at, auth.keys_changed_at):
        raise errors.invalid_keys_changed_at()
    # Having once sent a keysChangedAt, a client may not go back to omitting it:
    # the stored value would then be read as 0 and any key would look current.
    if auth.keys_changed_at is None and user.keys_changed_at not in (None, 0):
        raise errors.invalid_keys_changed_at()


def _apply(
    db: Database, auth: AuthData, user: SyncUser, now_ms: int
) -> tuple[int, int, int | None]:
    """`update_user`: move the record forward, or replace it. Returns the token's facts."""
    keys_changed_at = _next_keys_changed_at(auth, user)
    generation = _next_generation(auth, user)

    if auth.client_state != user.client_state:
        # A key rotation. The new key gets a new uid and therefore an empty
        # storage directory; the old row stays as history, and its records stay
        # where they are — unreadable under the new key, and nothing the client
        # asked us to delete.
        replacement = db.create_sync_user(
            fxa_uid=auth.fxa_uid,
            client_state=auth.client_state,
            generation=generation,
            keys_changed_at=keys_changed_at,
            created_at=now_ms,
        )
        db.replace_other_sync_users(auth.fxa_uid, keep=replacement.uid, replaced_at=now_ms)
        return replacement.uid, generation, keys_changed_at

    if generation != user.generation or keys_changed_at != user.keys_changed_at:
        db.update_sync_user(user.uid, generation=generation, keys_changed_at=keys_changed_at)
    return user.uid, generation, keys_changed_at


def _next_keys_changed_at(auth: AuthData, user: SyncUser) -> int | None:
    if auth.keys_changed_at is not None:
        # Validation has already established it is not lower than the stored one.
        return auth.keys_changed_at
    # No value in the request: hold at 0 if that is what is stored (validation
    # rejects anything else), and leave it unset if nothing ever set it.
    return None if user.keys_changed_at is None else 0


def _next_generation(auth: AuthData, user: SyncUser) -> int:
    if auth.generation is not None:
        return auth.generation
    # A client that reports no generation still reports keysChangedAt, and a key
    # change is an authentication change: let the one stand in for the other.
    if (
        auth.keys_changed_at is not None
        and auth.keys_changed_at > user.generation
        and (user.keys_changed_at is None or auth.keys_changed_at > user.keys_changed_at)
    ):
        return auth.keys_changed_at
    return user.generation


def _gt(left: int | None, right: int | None) -> bool:
    """`opt_cmp!(left > right)`: false unless both operands are present."""
    return left is not None and right is not None and left > right


def _lt(left: int | None, right: int | None) -> bool:
    return left is not None and right is not None and left < right


def _le(left: int | None, right: int | None) -> bool:
    return left is not None and right is not None and left <= right


__all__ = ["errors", "router", "tokenlib"]
