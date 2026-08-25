# fxa-lite: one process, one file of state, and an image that promises the same.
#
# Multi-stage, following astral's uv guidance.  The builder resolves the locked
# dependency set into /app/.venv; the runtime stage receives that directory and
# nothing else — no uv, no source tree, no build tooling.
#
# Both bases are pinned by digest rather than by tag, in the spirit of
# UPSTREAM.toml: a tag is a moving target and "we built against trixie-slim" is
# not a statement anybody can check later.  Each digest below is the multi-arch
# OCI index, so a single pin still builds linux/amd64 and linux/arm64.
#
# The uv image's provenance was attested by GitHub Actions and can be checked in
# one command before a pin is bumped:
#
#   gh attestation verify --owner astral-sh \
#       oci://ghcr.io/astral-sh/uv:0.11.29-python3.13-trixie-slim
#
# Build:
#   docker build -t fxa-lite .
#   docker buildx build --platform linux/amd64,linux/arm64 -t fxa-lite .

FROM ghcr.io/astral-sh/uv:0.11.29-python3.13-trixie-slim@sha256:0b973c14a35cb0dc8fe63a2e8c9919fd797ac566de13090fcf0df4a6b3994b78 AS builder

# UV_PYTHON_DOWNLOADS=0: use the interpreter the base image already has, which
# is the same Debian-built /usr/local/bin/python3.13 as the runtime stage — a
# downloaded standalone build would put a .venv in front of an interpreter that
# is not there at runtime.  UV_LINK_MODE=copy because the cache mount below is a
# different filesystem from /app, and hardlinks do not cross one.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Dependencies first, from a bind mount of just the two files that determine
# them, so editing a line of Python does not re-resolve cryptography.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev --no-editable

# --locked is also a free CI check: if uv.lock has drifted from pyproject.toml
# the build fails here rather than quietly resolving something else.
# --no-dev keeps pytest, ruff and ty out of a deployed image; --no-editable is
# what makes a source-free runtime stage possible, by installing the project
# into the venv instead of pointing at /app/src.
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable


FROM python:3.13-slim-trixie@sha256:7e3a6aca9d74f93cca21a91d86a8dad8c34749afd5b4a98ee481c9c47b9f5ed4

# Glibc, not musl: cryptography publishes manylinux wheels for amd64 and arm64,
# so the build stays a download.  On musl uv would fall back to an sdist that
# wants a Rust toolchain and OpenSSL headers — a fifteen-second build turned
# into a broken one, for no benefit here.

# uid 1000 is the one a bind-mounted /data has to be chowned to; a *named*
# volume inherits ownership from the image on first use and needs nothing.
# 0700 because /data holds the SQLite database (kA in the clear, and session
# token ids that are themselves the credential) and the signing key.
# Not --system: that reserves uids below SYS_UID_MAX (999) and warns about any
# other, and 1000 is deliberate — it is the uid a bind-mounted /data has to be
# chowned to, and the one a single-user host hands out first.
RUN groupadd --gid 1000 fxa \
    && useradd --uid 1000 --gid 1000 --home-dir /data --shell /usr/sbin/nologin fxa \
    && install --directory --owner fxa --group fxa --mode 0700 /data

COPY --from=builder --chown=root:root /app/.venv /app/.venv

# config.py resolves relative paths against the directory holding the config, so
# pointing FXA_LITE_CONFIG at /data/fxa.toml puts fxa.sqlite and
# signing-key.json beside it without a single flag.  That is the whole
# configuration surface of this image.
ENV PATH="/app/.venv/bin:$PATH" \
    FXA_LITE_CONFIG=/data/fxa.toml \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /data
USER fxa
EXPOSE 9000

# /__heartbeat__ rather than /__lbheartbeat__: it pings the database, so it can
# tell a failed volume mount from a healthy process.  No curl in a slim image,
# and adding one for this would be silly.  The port is the [listen] default; a
# deployment that changes it overrides this healthcheck in the compose file.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/__heartbeat__', timeout=4).read()"]

# ENTRYPOINT is the executable, so `docker compose run --rm fxa-lite keygen` and
# `... account add you@example.com` reach every subcommand without --entrypoint.
#
# Bootstrap stays interactive and stays manual.  There is deliberately no
# entrypoint script that mints a signing key when one is missing: a container
# that silently generates a key after a volume fails to mount looks like it
# recovered, while having invalidated every outstanding token.  cmd_serve
# already exits 1 with the right instruction, and the failure that is loud on a
# laptop must stay loud in a restart loop.
ENTRYPOINT ["/app/.venv/bin/fxa-lite"]

# --host 0.0.0.0 because [listen] host defaults to 127.0.0.1, which inside a
# network namespace means unreachable — including by the healthcheck above.
# The loopback binding moves to the host, where docker-compose.yaml publishes
# 127.0.0.1:9000 in front of whatever terminates TLS.
CMD ["serve", "--host", "0.0.0.0"]
