"""The container deliverables, checked without a container runtime.

`scripts/docker-smoke.sh` builds the image and proves these properties against
the real thing, which is the honest test and needs a daemon, several hundred
megabytes and a minute.  What is here instead are the claims that can be read
off the files themselves, and that go wrong quietly: a `.dockerignore` that
stops covering a secret `.gitignore` covers, a base image that drifts back to a
floating tag, an nginx body limit that no longer matches the one
`/info/configuration` advertises.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fxa_lite.syncstorage.models import LIMITS

ROOT = Path(__file__).resolve().parent.parent
DOCKERIGNORE = ROOT / ".dockerignore"
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yaml"
NGINX = ROOT / "deploy" / "nginx.conf.example"


def patterns(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def deployment_state_patterns() -> list[str]:
    """The `.gitignore` block that names the files a deployment must not leak."""
    block: list[str] = []
    collecting = False
    for line in (ROOT / ".gitignore").read_text().splitlines():
        if line.startswith("# Local deployment state"):
            collecting = True
            continue
        if collecting:
            if not line.strip():
                break
            block.append(line.strip())
    assert block, "the 'Local deployment state' block vanished from .gitignore"
    return block


@pytest.mark.parametrize("pattern", deployment_state_patterns())
def test_dockerignore_covers_every_gitignored_secret(pattern: str) -> None:
    """What is too sensitive to commit is too sensitive to bake into a layer.

    A `.dockerignore` pattern is matched against the path relative to the
    context root, so `*.sqlite` alone would match `./fxa.sqlite` and nothing
    deeper; `**/` is how the same pattern reaches any depth.  Either spelling
    counts here, since the files in question only ever sit at the root.
    """
    ignored = patterns(DOCKERIGNORE)
    assert pattern in ignored or f"**/{pattern}" in ignored


def test_dockerignore_excludes_the_upstream_checkouts() -> None:
    """844 MB of gitignored — therefore review-invisible — build context."""
    assert "resources/" in patterns(DOCKERIGNORE)


def test_dockerignore_keeps_what_the_build_needs() -> None:
    """The other failure mode: an exclusion that makes `uv sync` fail.

    `--no-editable` installs the project from the context, and pyproject.toml
    names README.md as the readme, so all four have to survive.
    """
    ignored = set(patterns(DOCKERIGNORE))
    for needed in ("pyproject.toml", "uv.lock", "README.md", "src", "src/"):
        assert needed not in ignored


def test_dockerignore_drops_the_development_interpreter_pin() -> None:
    """`.python-version` says 3.12; the base image is 3.13.

    Copied into the build it wins over the base image's interpreter and `uv
    sync` fails outright — which is how it was found.  The FROM line is the only
    place the image's Python version should be chosen.
    """
    assert ".python-version" in patterns(DOCKERIGNORE)


def test_base_images_are_pinned_by_digest() -> None:
    """A tag is a moving target, and `UPSTREAM.toml` is this project's opinion."""
    froms = re.findall(r"^FROM (\S+)", DOCKERFILE.read_text(), re.MULTILINE)
    assert len(froms) == 2, froms
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{image} is not pinned by digest"


def test_the_dockerfile_records_how_to_verify_the_uv_image() -> None:
    """The provenance check is one command; a pin nobody can check is a wish."""
    assert "gh attestation verify --owner astral-sh" in DOCKERFILE.read_text()


def test_the_container_binds_all_interfaces() -> None:
    """`[listen] host` defaults to 127.0.0.1, which inside a netns is nothing."""
    assert re.search(r'CMD \["serve", "--host", "0\.0\.0\.0"\]', DOCKERFILE.read_text())


def test_the_entrypoint_reaches_every_subcommand() -> None:
    """`docker compose run --rm fxa-lite keygen` must not need --entrypoint."""
    assert 'ENTRYPOINT ["/app/.venv/bin/fxa-lite"]' in DOCKERFILE.read_text()


def test_no_entrypoint_script_generates_a_key() -> None:
    """A container that mints a signing key when the volume failed to mount looks
    like it recovered, having invalidated every outstanding token."""
    assert not (ROOT / "docker-entrypoint.sh").exists()
    assert "keygen" not in re.sub(r"#.*", "", DOCKERFILE.read_text())


def test_the_healthcheck_pings_the_database() -> None:
    """/__lbheartbeat__ cannot tell a broken volume from a healthy process."""
    for path in (DOCKERFILE, COMPOSE):
        # Comments stripped: both files explain the choice, and the explanation
        # names the endpoint that was not chosen.
        text = re.sub(r"#.*", "", path.read_text())
        assert "/__heartbeat__" in text
        assert "/__lbheartbeat__" not in text


def test_compose_publishes_on_loopback_only() -> None:
    """The container binds 0.0.0.0; the loopback binding belongs on the host,
    in front of whatever terminates TLS."""
    published = re.findall(r'^\s*- "([^"]+:\d+)"', COMPOSE.read_text(), re.MULTILINE)
    app_ports = [entry for entry in published if entry.endswith(":9000")]
    assert app_ports == ["127.0.0.1:9000:9000"]


def test_compose_hardens_the_service() -> None:
    text = COMPOSE.read_text()
    for setting in ("read_only: true", 'cap_drop: ["ALL"]', "no-new-privileges:true"):
        assert setting in text


def test_nginx_allows_a_full_sync_batch() -> None:
    """/info/configuration advertises max_request_bytes and Firefox believes it.

    nginx's 1 MB default turns a history batch into a 413 the app never sees,
    and the client reads that as a stalled sync.
    """
    match = re.search(r"client_max_body_size\s+(\d+)([kKmMgG]?);", NGINX.read_text())
    assert match, "deploy/nginx.conf.example sets no client_max_body_size"
    scale = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[match.group(2).lower()]
    assert int(match.group(1)) * scale >= LIMITS.max_request_bytes


def test_nginx_passes_the_request_target_unrewritten() -> None:
    """Every `proxy_pass` is host-only: no URI part, so nothing is normalised.

    HAWK covers the target as sent, escapes included (`syncstorage._signed_target`).
    Giving `proxy_pass` a URI makes nginx rebuild the path it forwards, which
    would be invisible until a record id contained something that had to be
    escaped — and would then look like a signing bug in the client.
    """
    passes = re.findall(r"proxy_pass\s+(\S+);", NGINX.read_text())
    assert passes, "deploy/nginx.conf.example proxies nothing"
    assert all(target.count("/") == 2 for target in passes), passes


def test_nginx_ships_the_rate_limit_uncommented() -> None:
    """The audit's F3 decision: the per-IP half is required, not suggested —
    behind a proxy the app sees every client as 127.0.0.1 and cannot do it."""
    text = NGINX.read_text()
    assert re.search(r"^limit_req_zone\s", text, re.MULTILINE)
    limited = set(re.findall(r"location = (\S+) \{\n\s+limit_req\s", text))
    assert limited == {"/v1/account/login", "/v1/account/create", "/v1/session/reauth"}


def test_nginx_does_not_rewrite_paths() -> None:
    """HAWK signatures cover the URL the tokenserver handed out, and every URL
    it hands out comes from `public_url`: a prefix added or stripped here
    invalidates all of them at once."""
    text = NGINX.read_text()
    assert not re.search(r"^\s*rewrite\s", text, re.MULTILINE)
    # A proxy_pass with a path component is nginx's own way of rewriting.
    for target in re.findall(r"proxy_pass\s+(\S+);", text):
        assert re.fullmatch(r"https?://[\w.-]+", target), target


def test_nginx_sets_hsts() -> None:
    """The app does not, and a secure context is now a hard requirement: the
    sign-in page needs crypto.subtle to stretch the password at all."""
    assert "Strict-Transport-Security" in NGINX.read_text()
