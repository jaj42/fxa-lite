"""`UPSTREAM.toml` is the only record of what "the reference" is.

Every protocol constant in `plan.md` and every "matches the reference" comment in the source
was read out of a checkout under `resources/`, which is gitignored and untracked.  The manifest
pins each checkout to the commit that was read and lists the paths that were read from it, so
`scripts/upstream-diff.sh` can ask what upstream has done to those paths since.

The failure mode the manifest cannot survive on its own is a rename: upstream moves a file, the
path in the manifest stops matching anything, and the diff comes back *empty* — which reads
exactly like "nothing changed".  So the paths are checked twice, against two different commits.
Both checks are skipped when the checkout is absent; `resources/` is six hundred megabytes of
Node monorepo and no CI machine needs to clone it to run the rest of the suite.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "UPSTREAM.toml"
RESOURCES = ROOT / "resources"

REPOS: list[dict] = tomllib.loads(MANIFEST.read_text())["repo"]
BY_DIR = {repo["dir"]: repo for repo in REPOS}


def git(checkout: Path, *args: str) -> str:
    """Run git in a checkout, returning stdout; failures raise with git's own message."""
    result = subprocess.run(
        ["git", "-C", str(checkout), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def checkout_for(repo: dict) -> Path:
    """The checkout for one manifest entry, skipping the test if it is not cloned here."""
    checkout = RESOURCES / repo["dir"]
    if not (checkout / ".git").is_dir():
        pytest.skip(f"no checkout at resources/{repo['dir']}")
    return checkout


def ids(repos: list[dict]) -> list[str]:
    return [repo["dir"] for repo in repos]


def missing_at(checkout: Path, treeish: str, paths: list[str]) -> list[str]:
    """Which of `paths` name nothing in `treeish`.

    `ls-tree -r` so that a listed directory is matched by the files under it: without `-r` a
    pathspec that reaches deeper than a sibling suppresses that sibling's own tree entry, and
    the result reads as a missing path when nothing is missing.
    """
    listed = git(checkout, "ls-tree", "-r", "--name-only", "-z", treeish, "--", *paths)
    names = [name for name in listed.split("\0") if name]
    return sorted(
        path
        for path in paths
        if not any(name == path or name.startswith(f"{path}/") for name in names)
    )


# --- the manifest on its own, no checkouts needed ---------------------------------------


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_entry_is_complete(repo: dict) -> None:
    """A pin with no URL, no branch or no note is a pin nobody can act on."""
    assert repo.keys() == {"dir", "url", "branch", "commit", "date", "took", "paths"}
    assert repo["url"].startswith("https://")
    assert len(repo["commit"]) == 40, "pin the full sha — an abbreviation can become ambiguous"
    assert int(repo["commit"], 16) >= 0, "commit must be hex"
    assert repo["took"], "say what we took, or the entry cannot be triaged"
    assert repo["paths"], "an entry with no paths logs the whole repository"


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_paths_are_neither_duplicated_nor_nested(repo: dict) -> None:
    """A path already covered by a listed directory adds nothing but a second place to rot."""
    paths = repo["paths"]
    assert len(paths) == len(set(paths)), "duplicate path"
    for path in paths:
        parents = {str(parent) for parent in Path(path).parents}
        assert not parents & set(paths), f"{path} is already covered by a listed directory"


def test_every_checkout_is_pinned() -> None:
    """A checkout nobody recorded is a source nobody can cite — the gap this file closes."""
    if not RESOURCES.is_dir():
        pytest.skip("resources/ is not present")
    cloned = {path.name for path in RESOURCES.iterdir() if (path / ".git").is_dir()}
    assert cloned <= set(BY_DIR), f"unpinned checkout(s): {sorted(cloned - set(BY_DIR))}"


# --- the manifest against the checkouts -------------------------------------------------


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_pin_matches_the_checkout(repo: dict) -> None:
    """The pinned commit is in this clone, came from this URL, and carries the stated date."""
    checkout = checkout_for(repo)
    remotes = git(checkout, "remote", "get-url", "origin").removesuffix(".git")
    assert remotes == repo["url"].removesuffix(".git")
    assert git(checkout, "cat-file", "-t", repo["commit"]) == "commit", "pinned commit is absent"
    assert git(checkout, "show", "-s", "--format=%cs", repo["commit"]) == repo["date"]


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_paths_exist_at_the_pinned_commit(repo: dict) -> None:
    """The manifest describes what was read, so it has to describe the tree it was read from."""
    checkout = checkout_for(repo)
    missing = missing_at(checkout, repo["commit"], repo["paths"])
    assert not missing, f"not in {repo['commit'][:8]}: {missing}"


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_paths_still_exist_upstream(repo: dict) -> None:
    """The check that matters: a renamed path makes `upstream-diff.sh` report *nothing*.

    Run against the remote-tracking ref rather than the pin, and offline — a stale ref only
    delays the finding, where fetching in a test suite would make it flaky.  This is the one
    assertion that fires at the moment a pin is bumped past a rename, which is the only moment
    it can still be fixed cheaply.
    """
    checkout = checkout_for(repo)
    head = f"origin/{repo['branch']}"
    try:
        git(checkout, "rev-parse", "--verify", head)
    except AssertionError:
        pytest.skip(f"{repo['dir']}: no {head} — nothing to compare against")
    missing = missing_at(checkout, head, repo["paths"])
    assert not missing, (
        f"renamed or removed upstream, so upstream-diff.sh now under-reports: {missing}"
    )
