"""Finding `node`, and refusing to pretend it is optional in CI.

`tests/js/*.mjs` are the only coverage of `content/assets/*.js` — the password
stretching, the key unbundling and the `keys_jwe` seal all happen in the
browser, where pytest cannot reach them, and a mistake in any of it fails as
"Firefox signs in but never syncs" rather than as an error anyone can read.

Locally a missing `node` is a skip: not everyone hacking on the Python half has
a JavaScript runtime, and a suite that cannot be run at all is worse than one
that is honest about what it did not run.  In CI a skip is the failure mode
this project can least afford, because it is invisible — a green run that
exercised none of the browser crypto looks exactly like a green run that
exercised all of it.  So when `CI` is set, the absence of `node` fails.
"""

from __future__ import annotations

import os
import shutil

import pytest


def require_node(what: str) -> str:
    """Path to `node`, or skip — unless `CI` is set, in which case fail.

    `what` completes the sentence "node is not installed, so ...".
    """
    found = shutil.which("node")
    if found is not None:
        return found
    message = f"node is not installed, so {what}"
    if os.environ.get("CI"):
        pytest.fail(
            f"{message}. This is CI: the JavaScript suites are the only coverage of the "
            "browser-side crypto, so a runner without node is a configuration error, not a "
            "reason to skip. Add actions/setup-node to the workflow."
        )
    pytest.skip(message)
