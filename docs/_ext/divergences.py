# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Sphinx directive: render the `# DIVERGENCE:` markers as the provenance chapter.

`.. divergence-table::` (or ```{divergence-table}``` in MyST) walks `src/` at
build time and prints what it finds.  Nothing is authored here, so the chapter
cannot fall behind the code: a divergence that stops being one is documented as
gone by deleting its marker, and a marker whose fields are incomplete fails the
build.

Nodes are built by hand rather than by handing text back to the parser.  The
content is the same either way, but this way the page renders identically
whether the calling document is Markdown or reStructuredText, and a stray
backtick in a marker cannot turn into markup somewhere else on the page.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

from docutils import nodes
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxDirective

from divergence_scan import FIELDS, Divergence, scan

#: How each field is labelled in the rendered entry. The marker names are
#: chosen to read well in source; these read well on a page.
LABELS = {
    "upstream": "Upstream",
    "fxa-lite": "fxa-lite",
    "why": "Why",
    "cost": "What it costs",
}

_LITERAL_RE = re.compile(r"`([^`]+)`")


def inline(text: str) -> list[nodes.Node]:
    """Split on backticks, so `like_this` renders as code and the rest as prose."""
    built: list[nodes.Node] = []
    position = 0
    for match in _LITERAL_RE.finditer(text):
        if match.start() > position:
            built.append(nodes.Text(text[position : match.start()]))
        built.append(nodes.literal(match[1], match[1]))
        position = match.end()
    if position < len(text):
        built.append(nodes.Text(text[position:]))
    return built


def entry(divergence: Divergence, document: nodes.document) -> nodes.Element:
    """One divergence: a heading, four labelled paragraphs, and where it lives.

    The heading is also the cross-reference target, registered the way an
    explicit `.. _label:` would be. Sphinx gives a named `rubric` its own text
    as the link text, so `{ref}` picks up the divergence's title without the
    page that links to it having to repeat it.
    """
    label = f"divergence-{divergence.slug}"
    container = nodes.container(classes=["divergence"])
    heading = nodes.rubric(ids=[label], names=[label])
    heading += inline(divergence.title)
    document.note_explicit_target(heading)
    container += heading
    for name in FIELDS:
        paragraph = nodes.paragraph(classes=["divergence-field"])
        paragraph += nodes.strong(text=LABELS[name])
        paragraph += nodes.Text(" — ")
        paragraph += inline(divergence.fields[name])
        container += paragraph
    source = nodes.paragraph(classes=["divergence-source"])
    location = f"{divergence.path}:{divergence.line}"
    source += nodes.Text("Marked at ")
    source += nodes.literal(location, location)
    source += nodes.Text(f", slug {divergence.slug}.")
    container += source
    return container


class DivergenceTable(SphinxDirective):
    """`divergence-table` — every marker in the tree, grouped by tier."""

    has_content = False
    option_spec: ClassVar[dict[str, Any]] = {}

    def run(self) -> list[nodes.Node]:
        root = Path(self.env.srcdir).parent
        found = scan(root)
        # A rebuild has to notice a marker that changed in a .py file, and
        # Sphinx only watches its own sources. Every scanned file is declared a
        # dependency of this document, which is what makes that happen.
        for file in sorted((root / "src").rglob("*.py")):
            self.env.note_dependency(str(file))
        built: list[nodes.Node] = []
        tier = None
        for divergence in found:
            if divergence.tier != tier:
                tier = divergence.tier
                heading = nodes.rubric(classes=["divergence-tier"])
                heading += nodes.Text(tier)
                built.append(heading)
            built.append(entry(divergence, self.state.document))
        if not built:
            raise self.error("no DIVERGENCE markers found under src/")
        return built


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("divergence-table", DivergenceTable)
    return {"version": "1", "parallel_read_safe": True, "parallel_write_safe": True}
