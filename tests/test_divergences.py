# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The `# DIVERGENCE:` markers, and the chapter generated from them.

The markers are the single source: `docs/provenance.md` holds no authored copy
of the list, it holds a directive that walks `src/` at build time.  That removes
one drift risk and introduces another — a divergence can now disappear from the
documentation by having its marker deleted, which is exactly what a refactor
does to a comment it does not understand.

So the phase-10 list is pinned here by slug.  Each of those behaviours was
argued for once, in `AUDIT.md` or in `plan.md`, and each is still in the code;
if one of them stops being a divergence the right change is to delete the marker
*and* the row below, which is a change a reviewer can see.  A marker that is
merely moved to another file keeps passing, as it should.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "docs" / "_ext"))

from divergence_scan import FIELDS, MarkerError, parse, scan  # noqa: E402

#: Every divergence phase 10 collected, plus the ones phases 8, 11 and 13 added,
#: less `hawk-signs-decoded-path`, which phase 15 stopped being true of the code:
#: the MAC now covers the raw target, and what is left of that edge is the
#: narrower `bso-id-with-a-slash-unroutable`.
#: Sorted, because this is a set and not an order.
EXPECTED = {
    "access-tokens-not-revocable",
    "acr-values-refused",
    "avatar-is-always-a-monogram",
    "batch-append-filters-id",
    "bso-id-with-a-slash-unroutable",
    "device-commands-always-empty",
    "devices-notify-not-enabled",
    "failed-login-throttle",
    "hawk-macs-unverified",
    "hawk-payload-hash-verified",
    "metrics-disabled",
    "no-retry-after-on-permanent-403",
    "no-v2-upgrade",
    "quota-advertised-not-enforced",
    "registration-closed",
    "root-belongs-to-the-content-server",
    "strict-scope-validation",
    "sync-users-real-foreign-key",
    "tokenserver-audience-checked",
    "tokenserver-secret-derived",
    "wipe-clears-open-batches",
}


@pytest.fixture(scope="module")
def found() -> dict[str, object]:
    return {item.slug: item for item in scan(ROOT)}


def test_every_argued_divergence_is_still_marked(found: dict[str, object]) -> None:
    """The phase-10 list, in the code rather than in a document about the code."""
    assert EXPECTED - set(found) == set()


def test_no_divergence_is_marked_without_being_listed(found: dict[str, object]) -> None:
    """The other direction: a new marker has to be added here on purpose.

    Not bureaucracy — the point of the list is that somebody decided each entry
    was a divergence worth publishing. A marker nobody added here is a marker
    added by pattern-matching on the ones around it.
    """
    assert set(found) - EXPECTED == set()


@pytest.mark.parametrize("slug", sorted(EXPECTED))
def test_a_marker_carries_all_four_fields(found: dict, slug: str) -> None:
    """`scan` raises on a missing field; this says what the four are, by name."""
    divergence = found[slug]
    for name in FIELDS:
        assert divergence.fields[name].strip(), f"{slug} has an empty {name}"


@pytest.mark.parametrize("slug", sorted(EXPECTED))
def test_a_marker_sits_at_the_code_it_describes(found: dict, slug: str) -> None:
    """The line it names still exists, and is still a comment line of its own.

    A marker that has drifted off the end of its file — or into the middle of
    something after an edit — documents nothing, and the generated chapter would
    keep citing the stale location without complaint.
    """
    divergence = found[slug]
    lines = (ROOT / divergence.path).read_text().splitlines()
    assert divergence.line <= len(lines)
    assert lines[divergence.line - 1].strip().startswith("# DIVERGENCE:")


def test_a_marker_missing_a_field_is_an_error() -> None:
    with pytest.raises(MarkerError, match="cost"):
        parse(
            "# DIVERGENCE: half-written — a marker somebody stopped writing\n"
            "#   upstream: does the thing\n"
            "#   fxa-lite: does not\n"
            "#   why: reasons\n",
            path="somewhere.py",
        )


def test_a_field_continues_onto_the_next_comment_line() -> None:
    """Otherwise every field would have to be one very long line."""
    (divergence,) = parse(
        "# DIVERGENCE: wrapped — a marker whose prose does not fit\n"
        "#   upstream: first\n"
        "#     second\n"
        "#   fxa-lite: b\n"
        "#   why: c\n"
        "#   cost: d\n",
        path="somewhere.py",
    )
    assert divergence.fields["upstream"] == "first second"


def test_a_marker_ends_at_the_first_line_of_code() -> None:
    """A comment two lines below the block is not part of it."""
    (divergence,) = parse(
        "# DIVERGENCE: bounded — a marker followed by ordinary code\n"
        "#   upstream: a\n"
        "#   fxa-lite: b\n"
        "#   why: c\n"
        "#   cost: d\n"
        "def thing() -> None:\n"
        "    # why: not a field of the marker above\n"
        "    pass\n",
        path="somewhere.py",
    )
    assert divergence.fields["why"] == "c"


def test_a_hyphen_is_accepted_where_the_source_writes_an_em_dash() -> None:
    """The source uses an em dash; a keyboard gives you a hyphen."""
    (divergence,) = parse(
        "# DIVERGENCE: dashes - typed by somebody without a compose key\n"
        "#   upstream: a\n"
        "#   fxa-lite: b\n"
        "#   why: c\n"
        "#   cost: d\n",
        path="somewhere.py",
    )
    assert divergence.title == "typed by somebody without a compose key"
