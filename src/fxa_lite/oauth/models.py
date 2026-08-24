"""Request payloads for the OAuth tier, as the reference's joi schemas define them.

Same conventions as `auth/models.py`: the field names are the wire's, and
unknown keys are rejected rather than stripped.  The one thing worth reading
twice is `TokenRequest`, which upstream is a `Joi.alternatives()` over four
grant types; only two of them exist here, so the shape is one model plus an
explicit check that the fields present match the grant type claimed.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

#: `validators.clientId` — 8 bytes, hex.
ClientId = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{16}$")]
#: `validators.authorizationCode` / `unique.code` — 32 bytes, hex.
AuthorizationCode = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
#: `validators.refreshToken` / `unique.token` — 32 bytes, hex.
RefreshTokenValue = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
#: `PKCE_CODE_CHALLENGE_LENGTH` — base64url of a SHA-256 digest, always 43 chars.
CodeChallenge = Annotated[str, StringConstraints(min_length=43, max_length=43)]
#: RFC 7636 §4.1.
CodeVerifier = Annotated[str, StringConstraints(min_length=43, max_length=128)]


class OauthPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthorizationRequest(OauthPayload):
    """`POST /v1/oauth/authorization`, authenticated by a session token."""

    client_id: ClientId
    state: str = Field(max_length=512)
    # Only the code flow. `response_type=token` upstream is a legacy direct
    # grant for clients that predate PKCE; every client fxa-lite serves has it.
    response_type: str = "code"
    redirect_uri: str | None = Field(default=None, max_length=256)
    scope: str | None = Field(default=None, max_length=2048)
    access_type: str = "online"
    code_challenge_method: str | None = None
    code_challenge: CodeChallenge | None = None
    keys_jwe: str | None = Field(default=None, max_length=8192)
    acr_values: str | None = Field(default=None, max_length=256)
    max_age: int | None = Field(default=None, ge=0)
    #: `service=sync` stands in for a scope list the browser did not send.
    service: str | None = Field(default=None, max_length=32)
    prompt: str | None = None


class TokenRequest(OauthPayload):
    """`POST /v1/oauth/token` — `authorization_code`, `refresh_token` or
    `fxa-credentials`.

    The third is the direct grant, and it is here because Firefox Desktop will
    not sync without it: having completed the web flow it destroys the refresh
    token it was just issued and mints every subsequent access token straight
    from its session token.  Upstream that grant carries an `assertion`, which
    the auth server signs for itself and immediately verifies (`token.js`
    `makeAssertionJWT`); with one process there is nothing to assert to, so the
    session token authenticates the request directly and no `assertion` field
    exists here.

    `access_type` is legal only on `fxa-credentials`, matching the reference's
    `Joi.forbidden()` on every other grant type.
    """

    grant_type: str = "authorization_code"
    client_id: ClientId
    code: AuthorizationCode | None = None
    code_verifier: CodeVerifier | None = None
    redirect_uri: str | None = Field(default=None, max_length=256)
    refresh_token: RefreshTokenValue | None = None
    scope: str | None = Field(default=None, max_length=2048)
    access_type: str | None = None
    ttl: int | None = Field(default=None, gt=0)


class ScopedKeyDataRequest(OauthPayload):
    """`POST /v1/account/scoped-key-data`, authenticated by a session token."""

    client_id: ClientId
    scope: str = Field(max_length=2048)


class VerifyRequest(OauthPayload):
    token: str = Field(max_length=8192)


class IntrospectRequest(OauthPayload):
    token: str = Field(max_length=8192)
    token_type_hint: str | None = Field(default=None, max_length=64)


class DestroyRequest(OauthPayload):
    """RFC 7009 revocation. `client_id` is optional for historical reasons."""

    token: str = Field(max_length=8192)
    client_id: ClientId | None = None
    token_type_hint: str | None = Field(default=None, max_length=64)
