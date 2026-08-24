"""`ScopeSet` — OAuth scope values and the implication relation between them.

A port of `packages/fxa-shared/oauth/scopes.ts`.  Scope strings come in two
shapes, and both carry a hierarchy:

* **short names** — ``profile``, ``profile:email``, ``profile:email:write``.
  A prefix implies its extensions, and a ``:write`` scope implies the
  read-only scope of the same name (but never the reverse).
* **URL scopes** — ``https://identity.mozilla.com/apps/oldsync``.  A parent
  path implies its children, and a ``#fragment`` is carried along.

Everything the OAuth tier decides rests on `contains`: whether a client's
`allowedScopes` covers what was asked for, whether a granted token covers what
a profile route requires, whether the request asked for Sync at all.

The upstream implementation precomputes, for every scope value, the finite set
of scopes that would imply it — its *implicants* — which turns "does A imply
B?" into a string lookup.  That is reproduced here rather than reinvented with
prefix matching, because the edge cases (``profilebogey`` does not imply
``profile``; ``profile:email:write`` does not imply ``profile:write``) are
exactly the ones a hand-rolled version gets wrong.

Iteration order is part of the contract: `getScopeValues` upstream is
`Object.keys`, so a dict is used here and insertion order is preserved
identically.  Scope values are never integer-like, so JS and Python agree.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit, urlunsplit

#: RFC 6749 §3.3 — printable ASCII minus space, double quote and backslash.
_VALID_SCOPE_VALUE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
_VALID_SHORT_NAME = re.compile(r"^[a-zA-Z0-9_]+$")
_VALID_FRAGMENT = re.compile(r"^#[a-zA-Z0-9_]+$")
#: Characters the WHATWG URL parser percent-encodes inside a path (minus the
#: ones `_VALID_SCOPE_VALUE` already excludes), plus the backslash it rewrites
#: to a slash. Their presence means `value` is not its own canonical form.
_PATH_ESCAPES = re.compile(r"[<>`{}\\]")

#: Well above any legitimate scope; `profile:email:write` has three.
MAX_SHORT_SCOPE_COMPONENTS = 32


class InvalidScopeError(ValueError):
    """Raised for a scope string that is not well formed."""

    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid scope value: {value}")
        self.value = value


class ScopeSet:
    """A set of scope values, with set operations that respect implication."""

    __slots__ = ("_implicants_to_scopes", "_scopes_to_implicants")

    def __init__(self, scopes: Iterable[str] = ()) -> None:
        #: scope -> every scope that would imply it (itself included), in the
        #: order the derivation yields them. `implicant_values` reports that
        #: order verbatim, and the profile server's scope checks depend on it.
        self._scopes_to_implicants: dict[str, tuple[str, ...]] = {}
        #: implicant -> the scopes in this set that it implies.
        self._implicants_to_scopes: dict[str, set[str]] = {}
        for scope in scopes:
            self._add_scope(scope, _implicants(scope))

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_string(cls, value: str) -> ScopeSet:
        """Parse a space-delimited scope string, as RFC 6749 defines it."""
        return cls(part for part in re.split(r" +", value) if part)

    @classmethod
    def from_array(cls, values: Iterable[str]) -> ScopeSet:
        return cls(values)

    # -- inspection -----------------------------------------------------------

    def values(self) -> list[str]:
        """`getScopeValues` — the scopes actually held, redundancies removed."""
        return list(self._scopes_to_implicants)

    def implicant_values(self) -> list[str]:
        """`getImplicantValues` — every scope that would imply something here.

        Useful for reducing a repeated permission check to a string lookup,
        which is how the profile server matches a route's required scopes.
        """
        return list(self._implicants_to_scopes)

    def is_empty(self) -> bool:
        return not self._scopes_to_implicants

    def __bool__(self) -> bool:
        return bool(self._scopes_to_implicants)

    def __iter__(self) -> Iterator[str]:
        return iter(self._scopes_to_implicants)

    def __str__(self) -> str:
        return " ".join(self._scopes_to_implicants)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ScopeSet({str(self)!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScopeSet):
            return NotImplemented
        return set(self._scopes_to_implicants) == set(other._scopes_to_implicants)

    def __hash__(self) -> int:
        return hash(frozenset(self._scopes_to_implicants))

    # -- set operations -------------------------------------------------------

    def contains(self, other: ScopeSet | str | Iterable[str]) -> bool:
        """True when every scope in `other` is implied by a scope in here."""
        other = _coerce(other)
        return all(
            self._has_some_scope(implicants)
            for implicants in other._scopes_to_implicants.values()
        )

    def intersects(self, other: ScopeSet | str | Iterable[str]) -> bool:
        """True when either set implies at least one scope of the other."""
        other = _coerce(other)
        return any(
            implicant in self._scopes_to_implicants for implicant in other._implicants_to_scopes
        ) or any(
            implicant in other._scopes_to_implicants for implicant in self._implicants_to_scopes
        )

    def filtered(self, other: ScopeSet | str | Iterable[str]) -> ScopeSet:
        """The subset of this set that `other` implies — requested ∩ allowed.

        Not quite classical intersection: `profile:email:write` filtered by
        `profile` is empty, because a read-only scope implies no `:write` one.
        """
        other = _coerce(other)
        result = ScopeSet()
        for scope, implicants in self._scopes_to_implicants.items():
            if other._has_some_scope(implicants):
                result._add_scope(scope, implicants)
        return result

    def difference(self, other: ScopeSet | str | Iterable[str]) -> ScopeSet:
        """The subset of this set that `other` does *not* imply."""
        other = _coerce(other)
        result = ScopeSet()
        for scope, implicants in self._scopes_to_implicants.items():
            if not other._has_some_scope(implicants):
                result._add_scope(scope, implicants)
        return result

    def union(self, other: ScopeSet | str | Iterable[str]) -> ScopeSet:
        other = _coerce(other)
        result = ScopeSet()
        for scope, implicants in self._scopes_to_implicants.items():
            result._add_scope(scope, implicants)
        for scope, implicants in other._scopes_to_implicants.items():
            result._add_scope(scope, implicants)
        return result

    def add(self, other: ScopeSet | str | Iterable[str]) -> None:
        """Merge `other` in place, dropping whatever becomes redundant."""
        for scope, implicants in _coerce(other)._scopes_to_implicants.items():
            self._add_scope(scope, implicants)

    # -- internals ------------------------------------------------------------

    def _has_some_scope(self, scopes: Iterable[str]) -> bool:
        return any(scope in self._scopes_to_implicants for scope in scopes)

    def _add_scope(self, scope: str, implicants: tuple[str, ...]) -> None:
        # Already implied by something here: adding it would change nothing.
        if self._has_some_scope(implicants):
            return
        # It implies scopes we already hold; those are now redundant. Copy the
        # set first — _remove_scope mutates the mapping we would be iterating.
        for implied in list(self._implicants_to_scopes.get(scope, ())):
            self._remove_scope(implied)
        self._scopes_to_implicants[scope] = implicants
        for implicant in implicants:
            self._implicants_to_scopes.setdefault(implicant, set()).add(scope)

    def _remove_scope(self, scope: str) -> None:
        for implicant in self._scopes_to_implicants[scope]:
            implied = self._implicants_to_scopes[implicant]
            implied.discard(scope)
            if not implied:
                del self._implicants_to_scopes[implicant]
        del self._scopes_to_implicants[scope]


def _implicants(scope: str) -> tuple[str, ...]:
    """`implicant_values`, deduplicated but left in derivation order."""
    return tuple(dict.fromkeys(implicant_values(scope)))


def _coerce(value: ScopeSet | str | Iterable[str]) -> ScopeSet:
    if isinstance(value, ScopeSet):
        return value
    if isinstance(value, str):
        return ScopeSet.from_string(value)
    return ScopeSet(value)


def implicant_values(value: str) -> Iterator[str]:
    """Every scope value that would imply `value`, `value` itself included."""
    if value.startswith("https:"):
        return _url_implicants(value)
    return _short_implicants(value)


def _short_implicants(value: str) -> Iterator[str]:
    """`profile:email` is implied by `profile`, `profile:write`, itself, …

    Implication on short names is the prefix relation over the colon-separated
    components, with the rule that a `:write` scope implies the read-only one
    but a read-only scope implies no `:write` scope at all.
    """
    if not _VALID_SCOPE_VALUE.match(value):
        raise InvalidScopeError(value)
    # Bounded split: a pathological input must not build a huge list first.
    names = value.split(":", MAX_SHORT_SCOPE_COMPONENTS)
    if len(names) > MAX_SHORT_SCOPE_COMPONENTS:
        raise InvalidScopeError(value)
    for name in names:
        if not _VALID_SHORT_NAME.match(name):
            raise InvalidScopeError(value)
    has_write = names[-1] == "write"
    if has_write:
        names.pop()
        # "write" on its own is not a scope.
        if not names:
            raise InvalidScopeError(value)
    while names:
        joined = ":".join(names)
        yield f"{joined}:write"
        if not has_write:
            yield joined
        names.pop()


def _url_implicants(value: str) -> Iterator[str]:
    """`.../apps/oldsync/bookmarks` is implied by `.../apps/oldsync`, `.../apps`, …

    Upstream leans on `new URL()` and demands `url.href === value`, so anything
    the WHATWG parser would rewrite — a `..` segment, an uppercase host, a
    `%7B`-able character — is rejected rather than normalized.  Python's
    `urlsplit` normalizes none of that, so the rewrites are spelled out as
    rejections here.  Erring strict is the safe direction: a scope we refuse is
    a sign-in that fails loudly, while a scope we accept and the rest of the
    ecosystem spells differently is a key nobody can find again.
    """
    if not _VALID_SCOPE_VALUE.match(value):
        raise InvalidScopeError(value)
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise InvalidScopeError(value)
    # No credentials and no query: a scope must have exactly one spelling.
    if parts.username or parts.password or parts.query:
        raise InvalidScopeError(value)
    netloc = parts.netloc
    # The URL parser lowercases the host, punycodes it, and drops the default
    # port; a value written any of those other ways is not its own canonical form.
    if not netloc or not netloc.isascii() or netloc != netloc.lower():
        raise InvalidScopeError(value)
    if netloc.endswith(":443"):
        raise InvalidScopeError(value)
    if not parts.path or parts.path.endswith("/"):
        raise InvalidScopeError(value)
    segments = parts.path.split("/")
    if any(segment in (".", "..") for segment in segments):
        raise InvalidScopeError(value)
    if _PATH_ESCAPES.search(parts.path):
        raise InvalidScopeError(value)
    fragment = f"#{parts.fragment}" if parts.fragment else ""
    if fragment and not _VALID_FRAGMENT.match(fragment):
        raise InvalidScopeError(value)
    if urlunsplit(parts) != value:
        raise InvalidScopeError(value)

    origin = f"{parts.scheme}://{netloc}"
    path_parts = segments
    while len(path_parts) > 1:
        parent = origin + "/".join(path_parts)
        yield parent
        if fragment:
            yield parent + fragment
        path_parts.pop()
