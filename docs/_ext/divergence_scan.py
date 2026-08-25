"""Reading the `# DIVERGENCE:` markers out of the source tree.

Every place fxa-lite deliberately behaves unlike the reference carries a marker
at the code that does it:

    # DIVERGENCE: <slug> — <title>
    #   upstream: what the reference does
    #   fxa-lite: what this does instead
    #   why: the argument
    #   cost: what it takes away, and from whom

A field continues onto any following comment line that does not open a field of
its own, so the prose can be paragraphs rather than one enormous line.

This module is deliberately stdlib-only and knows nothing about Sphinx: it is
imported both by `divergences.py`, the extension that renders the chapter, and
by `tests/test_divergences.py`, which is the thing that stops a marker from
being deleted along with the behaviour it explains — or, more likely, from
being left behind after the behaviour stopped diverging.

The markers are the single source. The published table is generated from them
at build time, so there is no second copy to drift: a divergence documented and
not marked does not appear, and a marker whose fields are incomplete fails the
build rather than rendering a half-empty row.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: Field names every marker must carry, in the order they are rendered.
FIELDS = ("upstream", "fxa-lite", "why", "cost")

#: `# DIVERGENCE: some-slug — A sentence.` Either dash spelling is accepted;
#: an em dash is what the source uses and a hyphen is what a keyboard gives you.
_HEADER_RE = re.compile(r"^#\s*DIVERGENCE:\s*(?P<slug>[a-z0-9-]+)\s*[—-]\s*(?P<title>.+?)\s*$")
_FIELD_RE = re.compile(r"^#\s+(?P<name>upstream|fxa-lite|why|cost):\s*(?P<text>.*?)\s*$")
_CONTINUATION_RE = re.compile(r"^#\s+(?P<text>\S.*?)\s*$")

#: Which chapter of the architecture a marker belongs to, keyed on the first
#: path component below `fxa_lite/`. A file directly in the package root has no
#: component of its own and lands in the last bucket.
TIERS: tuple[tuple[str, str], ...] = (
    ("auth", "Accounts API"),
    ("oauth", "OAuth"),
    ("profile", "Profile"),
    ("content", "Content server"),
    ("tokenserver", "Sync tokenserver"),
    ("syncstorage", "Sync storage"),
    ("crypto", "Crypto core"),
    ("", "Across the process"),
)


class MarkerError(ValueError):
    """A marker that cannot be read as one. Always fatal: see the module docstring."""


@dataclass(frozen=True, slots=True)
class Divergence:
    """One marker, parsed."""

    slug: str
    title: str
    fields: dict[str, str]
    path: str
    line: int

    @property
    def tier(self) -> str:
        parts = Path(self.path).parts
        component = parts[2] if len(parts) > 3 else ""
        for prefix, name in TIERS:
            if prefix == component:
                return name
        return TIERS[-1][1]


def parse(text: str, *, path: str) -> list[Divergence]:
    """Every marker in one file's source, in the order they appear."""
    found: list[Divergence] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        header = _HEADER_RE.match(lines[index].strip())
        if header is None:
            index += 1
            continue
        start = index
        index += 1
        fields: dict[str, list[str]] = {}
        current: str | None = None
        while index < len(lines):
            stripped = lines[index].strip()
            if not stripped.startswith("#"):
                break
            if _HEADER_RE.match(stripped):
                break
            field = _FIELD_RE.match(stripped)
            if field is not None:
                current = field["name"]
                if current in fields:
                    raise MarkerError(
                        f"{path}:{index + 1}: {header['slug']} names {current} twice"
                    )
                fields[current] = [field["text"]] if field["text"] else []
            else:
                continuation = _CONTINUATION_RE.match(stripped)
                if continuation is None or current is None:
                    raise MarkerError(
                        f"{path}:{index + 1}: {header['slug']} has a line before its first "
                        f"field, or a field name that is not one of {', '.join(FIELDS)}"
                    )
                fields[current].append(continuation["text"])
            index += 1
        missing = [name for name in FIELDS if not fields.get(name)]
        if missing:
            raise MarkerError(
                f"{path}:{start + 1}: {header['slug']} is missing {', '.join(missing)}"
            )
        found.append(
            Divergence(
                slug=header["slug"],
                title=header["title"],
                fields={name: " ".join(fields[name]) for name in FIELDS},
                path=path,
                line=start + 1,
            )
        )
    return found


def scan(root: Path) -> list[Divergence]:
    """Every marker under `root/src`, sorted by tier and then by slug.

    Sorting by tier rather than by path is what makes the rendered chapter read
    in the same order as the architecture page: a reader who has just been told
    there are six tiers meets the divergences tier by tier.
    """
    found: list[Divergence] = []
    for file in sorted((root / "src").rglob("*.py")):
        found.extend(parse(file.read_text(encoding="utf-8"), path=str(file.relative_to(root))))
    order = {name: position for position, (_, name) in enumerate(TIERS)}
    found.sort(key=lambda item: (order[item.tier], item.slug))
    duplicates = {item.slug for item in found if [x.slug for x in found].count(item.slug) > 1}
    if duplicates:
        raise MarkerError(f"duplicate divergence slugs: {', '.join(sorted(duplicates))}")
    return found
