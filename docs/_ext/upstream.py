# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Sphinx directive: render `UPSTREAM.toml` as the "what we read" chapter.

`.. upstream-table::` prints one section per pinned checkout: where it is, the
commit fxa-lite was read against, what was taken from it, and — for the tracked
half — the paths that were actually read, each with the note `UPSTREAM.toml`
writes above it.

Both kinds of entry are rendered, and each says which it is rather than being
grouped under a heading that a reader arriving at one entry would not see.  A
`[[repo]]` is tracked: `scripts/upstream-diff.sh` follows its paths.  A
`[[reference]]` was read once, is pinned so a claim can cite a commit, and
carries no paths because nothing takes its diff.

Those notes are the reason this reads the file twice.  `tomllib` gives the
data and throws the comments away, and the comments are most of the value: a
path on its own says a directory was opened, while "hawk-fxa-token.js: the auth
scheme we match, MAC-discarding included" says what was found there.  So the
raw text is scanned a second time for the comment lines above each path, and
the two halves are matched up by path.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, ClassVar

from docutils import nodes
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxDirective

from divergences import inline


def notes(raw: str) -> dict[tuple[str, str], str]:
    """`(repo dir, path) -> the comment written above it`, from the file's text.

    A repo's `paths = [` block runs to the first `]` at the start of a line.
    Comment lines accumulate until a path consumes them, which is exactly how
    they are written: one note, then the one or more paths it covers.
    """
    collected: dict[tuple[str, str], str] = {}
    current = ""
    inside = False
    pending: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("dir = "):
            current = stripped.split("=", 1)[1].strip().strip('"')
            continue
        if stripped.startswith("paths = ["):
            inside = True
            pending = []
            continue
        if not inside:
            continue
        if stripped.startswith("]"):
            inside = False
            continue
        if stripped.startswith("#"):
            pending.append(stripped.lstrip("#").strip())
            continue
        path = stripped.rstrip(",").strip('"')
        if path:
            collected[(current, path)] = " ".join(pending)
            pending = []
    return collected


#: What each kind of entry promises, said at the entry rather than in a heading
#: the reader may have scrolled past.
KINDS = {
    "repo": "tracked — `upstream-diff.sh` follows the paths below",
    "reference": "read once, pinned so a claim can cite it; not tracked, no paths",
}


def repository(
    repo: dict[str, Any], comments: dict[tuple[str, str], str], kind: str
) -> list[nodes.Node]:
    built: list[nodes.Node] = []
    heading = nodes.rubric(classes=["upstream-repo", f"upstream-{kind}"])
    heading += nodes.Text(repo["dir"])
    built.append(heading)

    fields = nodes.field_list()
    for label, value in (
        ("Repository", repo["url"]),
        ("Branch", repo["branch"]),
        ("Commit", repo["commit"]),
        ("Read on", repo["date"]),
        ("Licence", repo["license"]),
        ("Kind", KINDS[kind]),
    ):
        field = nodes.field()
        field += nodes.field_name(text=label)
        body = nodes.field_body()
        paragraph = nodes.paragraph()
        if label == "Repository":
            paragraph += nodes.reference(value, value, refuri=value)
        elif label == "Commit":
            paragraph += nodes.literal(value, value)
        elif label == "Kind":
            paragraph += inline(value)
        else:
            paragraph += nodes.Text(value)
        body += paragraph
        field += body
        fields += field
    built.append(fields)

    took = nodes.paragraph()
    took += nodes.strong(text="What was taken: ")
    took += inline(repo["took"])
    built.append(took)

    if not repo.get("paths"):
        return built

    items = nodes.bullet_list(classes=["upstream-paths"])
    for path in repo["paths"]:
        item = nodes.list_item()
        paragraph = nodes.paragraph()
        paragraph += nodes.literal(path, path)
        note = comments.get((repo["dir"], path), "")
        if note:
            paragraph += nodes.Text(" — ")
            paragraph += inline(note)
        item += paragraph
        items += item
    built.append(items)
    return built


class UpstreamTable(SphinxDirective):
    """`upstream-table` — every entry in `UPSTREAM.toml`, in the order it is written."""

    has_content = False
    option_spec: ClassVar[dict[str, Any]] = {}

    def run(self) -> list[nodes.Node]:
        source = Path(self.env.srcdir).parent / "UPSTREAM.toml"
        self.env.note_dependency(str(source))
        raw = source.read_text(encoding="utf-8")
        data = tomllib.loads(raw)
        comments = notes(raw)
        built: list[nodes.Node] = []
        for kind in ("repo", "reference"):
            for repo in data.get(kind, []):
                built.extend(repository(repo, comments, kind))
        return built


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("upstream-table", UpstreamTable)
    return {"version": "1", "parallel_read_safe": True, "parallel_write_safe": True}
