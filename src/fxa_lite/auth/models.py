# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Request payloads, as the reference's joi schemas describe them.

Field names are the wire's — camelCase — because these classes *are* the wire
format.  Every constraint here is copied from `lib/routes/validators.js`; a
payload the reference would reject must not sneak through.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

#: `validators.HEX_STRING` applied to a 32-byte value.
Hex64 = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
Hex32 = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{32}$")]

#: `validators.isValidEmailAddress`, transcribed. Deliberately not pydantic's
#: `EmailStr`: that would pull in `email-validator`, and it disagrees with the
#: reference at the edges — an address the reference accepts but we reject is an
#: account that can never sign in.
_EMAIL_USER = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$", re.IGNORECASE)
_EMAIL_DOMAIN = re.compile(
    r"^[A-Z0-9](?:[A-Z0-9-]{0,253}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,253}[A-Z0-9])?)+$",
    re.IGNORECASE,
)


def _valid_email(value: str) -> str:
    local, separator, domain = value.partition("@")
    if not separator or "@" in domain or len(domain) > 255:
        raise ValueError("Not a valid email address")
    if not _EMAIL_USER.match(local):
        raise ValueError("Not a valid email address")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Not a valid email address") from exc
    if not _EMAIL_DOMAIN.match(ascii_domain):
        raise ValueError("Not a valid email address")
    return value


Email = Annotated[str, StringConstraints(max_length=255), AfterValidator(_valid_email)]


class Payload(BaseModel):
    """Base: reject unknown keys rather than ignore them.

    joi defaults to stripping unknown keys, but a typo'd field name that we
    silently ignore is a bug report that takes a week to track down.
    """

    model_config = ConfigDict(extra="forbid")


class AccountCreate(Payload):
    email: Email
    authPW: Hex64
    service: str | None = Field(default=None, max_length=16)
    redirectTo: str | None = None
    resume: str | None = Field(default=None, max_length=2048)
    verificationMethod: str | None = None
    preVerified: bool | None = None


class AccountLogin(Payload):
    email: Email
    authPW: Hex64
    service: str | None = Field(default=None, max_length=16)
    redirectTo: str | None = None
    resume: str | None = None
    reason: str | None = Field(default=None, max_length=16)
    verificationMethod: str | None = None
    originalLoginEmail: Email | None = None


class AccountStatusCheck(Payload):
    email: Email
    thirdPartyAuthStatus: bool = False
    checkDomain: str | None = None
    clientId: str | None = None
    service: str | None = None


class AccountDestroy(Payload):
    email: Email
    authPW: Hex64


class CredentialsStatus(Payload):
    email: Email


class SessionDestroy(Payload):
    customSessionToken: Hex64 | None = None


class SessionDuplicate(Payload):
    reason: str | None = Field(default=None, max_length=16)


class SessionReauth(Payload):
    email: Email
    authPW: Hex64
    service: str | None = Field(default=None, max_length=16)
    redirectTo: str | None = None
    resume: str | None = None
    reason: str | None = Field(default=None, max_length=16)
    verificationMethod: str | None = None
    originalLoginEmail: Email | None = None


class DeviceRegistration(Payload):
    id: Hex32 | None = None
    name: str | None = Field(default=None, max_length=255)
    type: str | None = Field(default=None, max_length=16)
    pushCallback: str | None = Field(default=None, max_length=255)
    pushPublicKey: str | None = Field(default=None, max_length=88)
    pushAuthKey: str | None = Field(default=None, max_length=24)
    availableCommands: dict[str, str] | None = None
    #: Some Firefox versions still send a zero-length array here. Accepted and
    #: dropped, exactly as upstream does.
    capabilities: list[str] | None = None


class DeviceDestroy(Payload):
    id: Hex32


class DevicesNotify(Payload):
    """`/account/devices/notify`, whose joi schema is two alternatives.

    `to` is either the string `all` — in which case `excluded` may name devices
    to skip — or an explicit list of device ids, in which case `excluded` is not
    a key of that alternative at all and so is rejected.  Firefox never sends
    both (`FxAccountsClient.notifyDevices` throws first), which is what makes
    the rule cheap to keep.

    The `payload` object is validated against `docs/pushpayloads.schema.json`
    upstream; that is a schema about what a *delivered* push may contain, and
    nothing here delivers one, so it is left as an object.
    """

    to: Literal["all"] | list[Hex32]
    payload: dict[str, Any]
    TTL: int | None = Field(default=None, ge=0)
    excluded: list[Hex32] | None = None
    #: Leading underscores are private in pydantic, so this one arrives by alias.
    endpointAction: Literal["accountVerify"] | None = Field(
        default=None, alias="_endpointAction"
    )

    @model_validator(mode="after")
    def _excluded_only_with_all(self) -> DevicesNotify:
        if self.excluded is not None and self.to != "all":
            raise ValueError("excluded is only valid when to is 'all'")
        return self
