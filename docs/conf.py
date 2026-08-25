"""Sphinx configuration.

Built with `-W`, so a broken cross-reference is a failed build rather than a
dead link on a published page. This documentation is very nearly nothing but
cross-references, which is the argument for the flag.

The pages are Markdown (MyST) because the README is Markdown and several pages
`include` pieces of it rather than copying them — the quickstart and the client
tables have exactly one source, and it is the file a reader lands on first.
"""

from __future__ import annotations

import sys
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent / "_ext"))

project = "fxa-lite"
author = "Jona JOACHIM"
copyright = f"{date.today().year}, {author}"  # noqa: A001 - Sphinx names this one
version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
release = version

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinxcontrib.mermaid",
    # docs/_ext: the two directives that generate a chapter each rather than
    # letting it be written twice. See their module docstrings.
    "divergences",
    "upstream",
]

exclude_patterns = ["_build"]
# `include` reaches outside `docs/` for the README, and Sphinx warns about a
# file it was not told to expect being read. Both of these are read, neither is
# a page.
suppress_warnings: list[str] = []

myst_enable_extensions = ["deflist", "attrs_block", "colon_fence"]
#: Anchors for headings up to `###`, so `[](page.md#some-heading)` resolves.
myst_heading_anchors = 3

html_theme = "furo"
html_title = f"fxa-lite {version}"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_theme_options = {
    "source_repository": "https://github.com/jaj42/fxa-lite/",
    "source_branch": "main",
    "source_directory": "docs/",
}

# Docstrings in this project carry the protocol constants and the traps, which
# is why `fxa_lite.crypto` is worth publishing at all. Members in source order:
# `onepw.py` reads as a narrative from `quickStretch` outwards, and alphabetical
# order would shuffle it.
autodoc_member_order = "bysource"
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_typehints = "description"
# `cryptography`'s key classes appear in nearly every signature in
# `fxa_lite.crypto` and have no intersphinx inventory to resolve against; with
# `-W` an unresolvable annotation would fail the build.
nitpicky = False
