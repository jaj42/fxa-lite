# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`ScopeSet`, pinned against the reference spec's own tables.

`tests/vectors/scopes.json` is a transcription of
`packages/fxa-shared/test/oauth/scopes.js`. The implication rules are subtle
enough — `profilebogey` does not imply `profile`, `profile:email:write` does
not imply `profile:write` — that anything short of the full table would pass
while getting the interesting cases wrong.
"""

import pytest

from fxa_lite.oauth.scopes import InvalidScopeError, ScopeSet
from vectors import load

VECTORS = load("scopes")


def _pair(vector: list[str]) -> tuple[ScopeSet, ScopeSet]:
    return ScopeSet.from_string(vector[0]), ScopeSet.from_string(vector[1])


@pytest.mark.parametrize("vector", VECTORS["valid_implications"], ids=" contains ".join)
def test_contains(vector) -> None:
    source, target = _pair(vector)
    assert source.contains(target)


@pytest.mark.parametrize("vector", VECTORS["invalid_implications"], ids=" excludes ".join)
def test_does_not_contain(vector) -> None:
    source, target = _pair(vector)
    assert not source.contains(target)


@pytest.mark.parametrize("value", VECTORS["invalid_values"])
def test_invalid_scope_values_are_rejected(value) -> None:
    with pytest.raises(InvalidScopeError):
        ScopeSet.from_string(value)


@pytest.mark.parametrize("vector", VECTORS["filtered"], ids=lambda v: f"{v[0]} | {v[1]}")
def test_filtered(vector) -> None:
    source, allowed = _pair(vector)
    assert str(source.filtered(allowed)) == vector[2]


@pytest.mark.parametrize("vector", VECTORS["intersections"], ids=" meets ".join)
def test_intersects(vector) -> None:
    first, second = _pair(vector)
    assert first.intersects(second)


@pytest.mark.parametrize("vector", VECTORS["non_intersections"], ids=" misses ".join)
def test_does_not_intersect(vector) -> None:
    first, second = _pair(vector)
    assert not first.intersects(second)


@pytest.mark.parametrize("vector", VECTORS["implicants"], ids=lambda v: v[0])
def test_implicant_values(vector) -> None:
    """Order matters: the profile server turns this list into a scope check."""
    assert " ".join(ScopeSet.from_string(vector[0]).implicant_values()) == vector[1]


@pytest.mark.parametrize("vector", VECTORS["unions"], ids=lambda v: f"{v[0]} + {v[1]}")
def test_union(vector) -> None:
    first, second = _pair(vector)
    assert str(first.union(second)) == vector[2]


@pytest.mark.parametrize("vector", VECTORS["differences"], ids=lambda v: f"{v[0]} - {v[1]}")
def test_difference(vector) -> None:
    first, second = _pair(vector)
    assert str(first.difference(second)) == vector[2]


def test_add_aggregates_in_place() -> None:
    sequence = VECTORS["add_sequence"]
    scopes = ScopeSet.from_string(sequence["start"])
    assert str(scopes) == sequence["start"]
    for added, expected in sequence["steps"]:
        scopes.add(added)
        assert str(scopes) == expected


def test_emptiness() -> None:
    assert ScopeSet.from_string("").is_empty()
    assert not ScopeSet.from_string("profile").is_empty()


def test_redundant_scopes_are_dropped() -> None:
    """`profile` subsumes `profile:email`, so only one value is stored."""
    assert ScopeSet.from_string("profile profile:email").values() == ["profile"]
