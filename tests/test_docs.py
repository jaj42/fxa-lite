# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The documentation build, and the two ways it is wired to the rest of the tree.

Nothing here renders HTML — `sphinx-build -W` does that in CI, and repeating it
under pytest would cost a minute a run to catch what the workflow already
catches.  What is checked instead are the joints, which are the parts that break
silently:

* the README is included into the docs by marker, so a marker renamed or removed
  leaves a page quietly missing its quickstart;
* every page under `docs/` is reachable from the toctree, because an orphan page
  builds cleanly, publishes, and is linked from nowhere;
* the workflows still do what they were written to do — in particular that CI
  installs `node`, without which the browser-crypto suites are the failure
  `tests/nodejs.py` is designed to raise.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import pytest

from nodejs import require_node

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
README = ROOT / "README.md"
WORKFLOWS = ROOT / ".github" / "workflows"

#: `<!-- include: name -->` … `<!-- end: name -->` in the README, quoted by a
#: `{include}` in the docs. One source, two renderings.
INCLUDES = ("quickstart", "docker-quickstart", "desktop-prefs", "android-fields")


@pytest.mark.parametrize("name", INCLUDES)
def test_the_readme_still_carries_its_include_markers(name: str) -> None:
    text = README.read_text()
    assert f"<!-- include: {name} -->" in text
    assert f"<!-- end: {name} -->" in text


@pytest.mark.parametrize("name", INCLUDES)
def test_each_marked_block_is_included_somewhere(name: str) -> None:
    """A marker nothing reads is a marker the next edit deletes."""
    wanted = f":start-after: <!-- include: {name} -->"
    assert any(wanted in page.read_text() for page in DOCS.glob("*.md"))


@pytest.mark.parametrize("name", INCLUDES)
def test_a_marked_block_is_not_empty(name: str) -> None:
    """Markers that have drifted onto adjacent lines still parse and say nothing."""
    body = README.read_text().split(f"<!-- include: {name} -->", 1)[1]
    body = body.split(f"<!-- end: {name} -->", 1)[0]
    assert len(body.strip()) > 40


def test_every_page_is_in_the_toctree() -> None:
    """An orphan page builds, publishes, and is reachable from nothing."""
    index = (DOCS / "index.md").read_text()
    listed = set(re.findall(r"^([a-z_]+)$", index, flags=re.MULTILINE))
    pages = {page.stem for page in DOCS.glob("*.md")} - {"index"}
    assert pages - listed == set()


def test_the_docs_group_is_not_a_runtime_dependency() -> None:
    """Sphinx must never end up in the wheel; `src/` may not import any of it."""
    for source in (ROOT / "src").rglob("*.py"):
        text = source.read_text()
        for package in ("sphinx", "myst_parser", "furo", "docutils"):
            assert f"import {package}" not in text, f"{source} imports {package}"


@pytest.fixture(scope="module")
def ci() -> str:
    return (WORKFLOWS / "ci.yml").read_text()


@pytest.fixture(scope="module")
def docs() -> str:
    return (WORKFLOWS / "docs.yml").read_text()


class TestCiWorkflow:
    def test_it_installs_node(self, ci: str) -> None:
        """Without this the browser-crypto suites fail, by design. See nodejs.py."""
        assert "actions/setup-node" in ci

    @pytest.mark.parametrize(
        "command", ["uv run pytest", "uv run ruff check", "uv run ty check"]
    )
    def test_it_runs_the_three_checks_every_phase_claimed(
        self, ci: str, command: str
    ) -> None:
        assert command in ci

    def test_it_builds_the_image(self, ci: str) -> None:
        assert "docker/build-push-action" in ci
        assert "push: false" in ci

    def test_it_installs_from_the_lockfile(self, ci: str) -> None:
        """`--locked`, so a stale `uv.lock` fails rather than resolving around it."""
        assert "uv sync --locked" in ci


class TestDocsWorkflow:
    def test_it_builds_with_warnings_as_errors(self, docs: str) -> None:
        """`-W`: this documentation is very nearly nothing but cross-references."""
        assert "sphinx-build -W" in docs

    def test_it_asks_for_the_permissions_pages_needs(self, docs: str) -> None:
        assert "pages: write" in docs
        assert "id-token: write" in docs

    def test_it_deploys_only_from_main(self, docs: str) -> None:
        """A pull request builds the site; it does not publish it."""
        assert "actions/deploy-pages" in docs
        assert "refs/heads/main" in docs


def test_a_ci_runner_without_node_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point of `tests/nodejs.py`, exercised without uninstalling node.

    `pytest.fail.Exception` rather than `Exception`: both outcomes derive from
    `BaseException`, so catching `Exception` here would catch neither and the
    test would pass by not running.
    """
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setitem(os.environ, "CI", "true")
    with pytest.raises(pytest.fail.Exception, match="configuration error"):
        require_node("nothing can be checked")


def test_a_laptop_without_node_merely_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not everyone hacking on the Python half has a JavaScript runtime."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(pytest.skip.Exception, match="not installed"):
        require_node("nothing can be checked")
