# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""`UPSTREAM.toml` is the only record of what "the reference" is.

Every protocol constant in `plan.md` and every "matches the reference" comment in the source
was read out of a checkout under `resources/`, which is gitignored and untracked.  The manifest
pins each checkout to the commit that was read, so a claim can name its source.

It holds two kinds of entry and they promise different things.  `[[repo]]` is *tracked*:
functionality fxa-lite replicates, listed down to the paths that were read so
`scripts/upstream-diff.sh` can ask what upstream has done to them since.  `[[reference]]` is
*cited*: read once to answer one question — mostly about the client on the other side of the
wire — pinned so the answer names a commit, and never diffed, which is why it carries no paths.

The failure mode the tracked half cannot survive on its own is a rename: upstream moves a file,
the path in the manifest stops matching anything, and the diff comes back *empty* — which reads
exactly like "nothing changed".  So tracked paths are checked twice, against two different
commits.  References are exempt because nothing takes their diff; what they must still do is
resolve, since a citation to a commit that is not there is not a citation.

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

_MANIFEST = tomllib.loads(MANIFEST.read_text())

#: The two repositories fxa-lite replicates and stays current with.
REPOS: list[dict] = _MANIFEST["repo"]
#: Read once, pinned so a claim can cite a commit.  Never diffed.
REFERENCES: list[dict] = _MANIFEST.get("reference", [])
#: Every pin, of either kind.  A checkout has to be one or the other.
ALL: list[dict] = [*REPOS, *REFERENCES]

BY_DIR = {entry["dir"]: entry for entry in ALL}

#: Changing this set is the decision, not a consequence of one — see `test_only_two_...`.
TRACKED = {"fxa", "syncstorage-rs"}


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


def checkout_for(entry: dict) -> Path:
    """The checkout for one manifest entry, skipping the test if it is not cloned here."""
    checkout = RESOURCES / entry["dir"]
    if not (checkout / ".git").is_dir():
        pytest.skip(f"no checkout at resources/{entry['dir']}")
    return checkout


def ids(entries: list[dict]) -> list[str]:
    return [entry["dir"] for entry in entries]


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


def test_only_two_repositories_are_tracked() -> None:
    """Tracking is a promise to stay current, and it is only made about what we replicate.

    Everything else fxa-lite has read is a `[[reference]]`: pinned so a claim can cite it,
    never followed for change.  Promoting a third repository means taking on its diff
    forever, so it has to be an edit somebody made on purpose rather than one that happened
    while adding a citation.
    """
    assert {repo["dir"] for repo in REPOS} == TRACKED


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_entry_is_complete(repo: dict) -> None:
    """A pin with no URL, no branch or no note is a pin nobody can act on."""
    assert repo.keys() == {"dir", "url", "branch", "commit", "date", "license", "took", "paths"}
    assert repo["paths"], "an entry with no paths logs the whole repository"


@pytest.mark.parametrize("entry", REFERENCES, ids=ids(REFERENCES))
def test_reference_entry_is_complete(entry: dict) -> None:
    """A reference is a citation, so it needs everything but the path list — and not that.

    Paths exist to be diffed and nothing diffs a reference; one that grew them would be a
    repository somebody started tracking without saying so, and without paying for it in
    `upstream-diff.sh`.  What a reference actually supports is written at the claim, in
    `BUGS.md` or in `docs/`, which is the only place a reader can check it.
    """
    assert entry.keys() == {"dir", "url", "branch", "commit", "date", "license", "took"}


@pytest.mark.parametrize("entry", ALL, ids=ids(ALL))
def test_pin_is_well_formed(entry: dict) -> None:
    assert entry["url"].startswith("https://")
    assert len(entry["commit"]) == 40, "pin the full sha — an abbreviation can become ambiguous"
    assert int(entry["commit"], 16) >= 0, "commit must be hex"
    assert entry["took"], "say what we took, or the entry cannot be triaged"


@pytest.mark.parametrize("entry", ALL, ids=ids(ALL))
def test_the_licence_is_recorded(entry: dict) -> None:
    """fxa-lite's own licence is an argument about these, so each one has to be stated.

    Every entry that was *taken* from is MPL-2.0, and the ones under harder terms — IronFox
    is AGPL-3.0, jwcrypto LGPL-3.0, fxa-self-hosting has no LICENSE at all — are exactly the
    ones whose `took` line says "nothing".  A new entry added without this key is a new
    entry added without anybody asking the question.  See `docs/provenance.md`, *Licensing*.
    """
    assert entry["license"], f"{entry['dir']}: no licence recorded"


@pytest.mark.parametrize("repo", REPOS, ids=ids(REPOS))
def test_paths_are_neither_duplicated_nor_nested(repo: dict) -> None:
    """A path already covered by a listed directory adds nothing but a second place to rot."""
    paths = repo["paths"]
    assert len(paths) == len(set(paths)), "duplicate path"
    for path in paths:
        parents = {str(parent) for parent in Path(path).parents}
        assert not parents & set(paths), f"{path} is already covered by a listed directory"


def test_every_checkout_is_pinned() -> None:
    """A checkout nobody recorded is a source nobody can cite — the gap this file closes.

    Either kind counts.  Splitting the manifest narrowed what is *tracked* to two
    repositories; it did not narrow what is *recorded*, and this is the assertion that keeps
    the two questions apart.  A clone that is neither a `[[repo]]` nor a `[[reference]]` is
    something somebody read and did not write down.
    """
    if not RESOURCES.is_dir():
        pytest.skip("resources/ is not present")
    cloned = {path.name for path in RESOURCES.iterdir() if (path / ".git").is_dir()}
    assert cloned <= set(BY_DIR), f"unpinned checkout(s): {sorted(cloned - set(BY_DIR))}"


# --- the manifest against the checkouts -------------------------------------------------


@pytest.mark.parametrize("entry", ALL, ids=ids(ALL))
def test_pin_matches_the_checkout(entry: dict) -> None:
    """The pinned commit is in this clone, came from this URL, and carries the stated date.

    Both kinds, because this is what makes a pin a citation rather than a decoration.
    """
    checkout = checkout_for(entry)
    remotes = git(checkout, "remote", "get-url", "origin").removesuffix(".git")
    assert remotes == entry["url"].removesuffix(".git")
    assert git(checkout, "cat-file", "-t", entry["commit"]) == "commit", "pinned commit is absent"
    assert git(checkout, "show", "-s", "--format=%cs", entry["commit"]) == entry["date"]


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
    it can still be fixed cheaply.  Tracked entries only: nothing takes a reference's diff, so
    a rename there costs a manual `git log` and not a silence.
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
