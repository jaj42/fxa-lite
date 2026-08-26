# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Just enough User-Agent parsing to name a device.

The reference runs a full UA database to fill `uaBrowser`, `uaOS` and friends,
and uses them for the connected-devices UI.  All fxa-lite needs is the fallback
name for a device that registered without one — Firefox always sends its own —
so this recognises the browsers that can actually reach a Sync server and gives
up gracefully on everything else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_BROWSER_RE = re.compile(
    r"(Firefox|FxiOS|Fennec|Focus|SeaMonkey|Thunderbird)/(\d+)[\d.]*", re.IGNORECASE
)
_OS_PATTERNS = (
    (re.compile(r"Windows NT [\d.]+"), "Windows"),
    (re.compile(r"Android"), "Android"),
    (re.compile(r"(iPhone|iPad|iPod)"), "iOS"),
    (re.compile(r"Mac OS X"), "Mac OS X"),
    (re.compile(r"CrOS"), "Chrome OS"),
    (re.compile(r"(Linux|X11)"), "Linux"),
)
#: The `FxiOS`/`Fennec` spellings are not what a user should read on screen.
_BROWSER_NAMES = {"fxios": "Firefox", "fennec": "Firefox"}


@dataclass(frozen=True, slots=True)
class UserAgent:
    browser: str = ""
    browser_version: str = ""
    os: str = ""

    @property
    def is_mobile(self) -> bool:
        return self.os in ("Android", "iOS")


def parse(user_agent: str) -> UserAgent:
    browser = version = ""
    match = _BROWSER_RE.search(user_agent or "")
    if match:
        name = match.group(1)
        browser = _BROWSER_NAMES.get(name.lower(), name)
        version = match.group(2)
    operating_system = ""
    for pattern, label in _OS_PATTERNS:
        if pattern.search(user_agent or ""):
            operating_system = label
            break
    return UserAgent(browser=browser, browser_version=version, os=operating_system)


def synthesize(parsed: UserAgent) -> str:
    """`synthesizeClientName` — "Firefox 130, Linux", or as much of it as we know."""
    parts = []
    if parsed.browser:
        parts.append(f"{parsed.browser} {parsed.browser_version}".strip())
    if parsed.os:
        parts.append(parsed.os)
    return ", ".join(parts)


def synthesize_name(user_agent: str) -> str:
    return synthesize(parse(user_agent))


def describe(parsed: UserAgent) -> str:
    """The `userAgent` field of an attached client: browser and major version.

    Upstream splits `uaBrowserVersion` at the first dot here; `parse` has
    already kept only the major, so there is nothing left to split.
    """
    if not parsed.browser:
        return ""
    return f"{parsed.browser} {parsed.browser_version}".strip()
