# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The licence, and the argument that picked it.

fxa-lite is MPL-2.0.  That is not a preference — it is a conclusion, and the
premises are in `UPSTREAM.toml`: every project fxa-lite *took* from is MPL-2.0,
and the three whose terms would have constrained harder (IronFox is AGPL-3.0,
jwcrypto LGPL-3.0, fxa-self-hosting has no LICENSE at all) are exactly the three
whose `took` line says "nothing".  So the tests here are not decoration around a
file nobody reads.  `test_anything_taken_from_is_mpl` is the premise itself: add
a reference under harder terms, take something from it, and the conclusion stops
following — which is the moment somebody needs to notice, not the release after.

MPL-2.0 is file-level copyleft (§1.10, §3.1), so §3.1's notice requirement lands
on the files that are Modifications — and fxa-lite has real ones, ports and
transcriptions rather than only independent work.  Applying Exhibit A uniformly
is cheaper than maintaining a list of which files are derived and which are not,
and that uniformity is what `test_every_source_file_carries_exhibit_a` keeps.

See `docs/provenance.md`, *Licensing*, for the reasoning in full.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LICENSE = ROOT / "LICENSE"
PYPROJECT = ROOT / "pyproject.toml"
MANIFEST = ROOT / "UPSTREAM.toml"

#: The SPDX identifier, in the one place a machine reads it and the one a human does.
SPDX = "MPL-2.0"

#: Exhibit A, in the two comment syntaxes this tree uses.  Matched on the first
#: line only, so a file may reflow the rest.
NOTICE = "This Source Code Form is subject to the terms of the Mozilla Public"

#: Directories of first-party source.  `docs/_ext` is in because Sphinx extensions
#: are Python that `ruff` and `ty` read like any other file; `docs/_build` is out
#: because it is generated.
SOURCE_ROOTS = ("src", "tests", "docs/_ext", "scripts")

SOURCE_SUFFIXES = (".py", ".js", ".mjs", ".sh")

#: Files exempt from the notice, each with the reason.  Deliberately empty: there
#: is no file in this tree where the notice is impossible or undesirable, which is
#: the condition Exhibit A itself attaches to putting it in a LICENSE file instead.
#: An entry added here is a claim, so it needs a reason beside it.
EXEMPT: dict[str, str] = {}


def sources() -> list[Path]:
    found = []
    for root in SOURCE_ROOTS:
        for path in sorted((ROOT / root).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix in SOURCE_SUFFIXES:
                found.append(path)
    return found


SOURCES = sources()
MANIFEST_ENTRIES: list[dict] = [
    *tomllib.loads(MANIFEST.read_text())["repo"],
    *tomllib.loads(MANIFEST.read_text()).get("reference", []),
]


def test_the_licence_file_is_the_mpl() -> None:
    """Not merely present — the right text.  A stub LICENSE is worse than none."""
    assert LICENSE.is_file(), "no LICENSE file: the repository is all-rights-reserved"
    text = LICENSE.read_text()
    assert text.splitlines()[0].strip() == "Mozilla Public License Version 2.0"
    assert "Exhibit A - Source Code Form License Notice" in text
    assert NOTICE in text


def test_the_package_metadata_agrees_with_the_licence_file() -> None:
    """PEP 639: an SPDX expression plus the file, so a wheel carries both."""
    data = tomllib.loads(PYPROJECT.read_text())["project"]
    assert data["license"] == SPDX
    assert data["license-files"] == ["LICENSE"]


@pytest.mark.parametrize("path", SOURCES, ids=[str(p.relative_to(ROOT)) for p in SOURCES])
def test_every_source_file_carries_exhibit_a(path: Path) -> None:
    """§3.1 asks for the notice on Covered Software, and we do not maintain a map.

    Checked against the head of the file rather than the whole of it, so a string
    mentioning the MPL somewhere in the body cannot satisfy this by accident.
    """
    relative = str(path.relative_to(ROOT))
    if relative in EXEMPT:
        pytest.skip(f"exempt: {EXEMPT[relative]}")
    assert NOTICE in path.read_text()[:400], f"{relative}: no MPL notice at the top"


@pytest.mark.parametrize("path", SOURCES, ids=[str(p.relative_to(ROOT)) for p in SOURCES])
def test_the_notice_comes_after_any_shebang(path: Path) -> None:
    """A notice above `#!` stops the file being executable, which is a silent break."""
    lines = path.read_text().splitlines()
    if lines[0].startswith("#!"):
        assert NOTICE not in lines[0], "the notice displaced the shebang"
        assert NOTICE in lines[1], "the notice does not follow the shebang"
    else:
        assert NOTICE in lines[0], "the notice is not the first line"


@pytest.mark.parametrize(
    "entry", MANIFEST_ENTRIES, ids=[entry["dir"] for entry in MANIFEST_ENTRIES]
)
def test_anything_taken_from_is_mpl(entry: dict) -> None:
    """The premise fxa-lite's own licence rests on.

    An entry whose `took` begins "nothing" imposes no terms on this repository —
    which is the whole reason those lines are written that way, and why IronFox
    (AGPL-3.0) and jwcrypto (LGPL-3.0) being in the manifest costs nothing.  Every
    other entry contributed something, so its licence has to be one fxa-lite's own
    can carry, and MPL-2.0 is the only one that has ever appeared there.

    If this fails, the fix is not to widen the assertion.  It is to decide whether
    the thing taken really was taken, and if so what that does to `LICENSE`.
    """
    if entry["took"].lower().startswith("nothing"):
        return
    assert entry["license"] == SPDX, (
        f"{entry['dir']} is {entry['license']} and something was taken from it: "
        f"{entry['took'][:80]}…"
    )
