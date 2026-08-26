#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Does the container image actually deploy, and does it ship anything it should not?
#
# Builds the image, then drives the documented bootstrap end to end —
#
#   keygen  ->  account add  ->  serve  ->  a browser's first two requests
#
# — against a throwaway named volume, and asserts the two properties that are
# easy to claim and easy to get wrong:
#
#   * no deployment secret is baked into a layer.  `.dockerignore` is what keeps
#     fxa.toml, the SQLite database and the signing key out of an image that may
#     be pushed to a registry, and "I checked once" is exactly the kind of claim
#     CI exists to stop this project from making.
#
#   * `keygen` inside the container writes the signing key 0600 *and owns it*.
#     The mode guarantee is worthless if the file belongs to a different uid
#     than the one `serve` runs as.
#
# Usage:  scripts/docker-smoke.sh [--keep] [--no-build]
#
#   --keep      leave the container, volumes and image behind for poking at
#   --no-build  reuse an existing $IMAGE (fastest loop when editing this script)
#
# Environment: DOCKER (default `docker`; `podman` works), IMAGE, PORT.
#
# Exit status is 0 only if every assertion passed.  Needs curl and openssl on
# the host; the nginx step is skipped if the example config is absent.

set -uo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
docker=${DOCKER:-docker}
image=${IMAGE:-fxa-lite:smoke}
port=${PORT:-9010}
container=fxa-lite-smoke
volume=fxa-lite-smoke-data
empty_volume=fxa-lite-smoke-empty

public_url=https://fxa.smoke.example
email=smoke@example.com
password=smoke-test-password-not-a-real-one

keep=0
build=1
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    --no-build) build=0 ;;
    -h | --help)
      awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

failures=0
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '  ok    %s\n' "$*"; }
bad() {
  printf '  FAIL  %s\n' "$*" >&2
  failures=$((failures + 1))
}
# For a known, triaged, not-yet-fixed finding: worth printing every run, not
# worth leaving the deliverable red over.
warn() { printf '  warn  %s\n' "$*"; }

# One assertion helper, so a failure never aborts the run: the interesting
# output is the *set* of things that broke, and a container left half-started.
expect_contains() {
  local what=$1 haystack=$2 needle=$3
  if [[ $haystack == *"$needle"* ]]; then
    ok "$what"
  else
    bad "$what — expected to find '$needle' in: ${haystack:0:400}"
  fi
}

cleanup() {
  [ "$keep" -eq 1 ] && {
    printf '\nkept: container %s, volumes %s / %s, image %s\n' \
      "$container" "$volume" "$empty_volume" "$image"
    return
  }
  $docker rm --force "$container" >/dev/null 2>&1
  $docker volume rm --force "$volume" "$empty_volume" >/dev/null 2>&1
  rm -rf "$certs"
}
certs=$(mktemp -d)
trap cleanup EXIT

# Same hardening the compose file applies, so the smoke test exercises the
# deployment rather than a friendlier version of it.
harden=(
  --user 1000:1000
  --read-only
  --tmpfs /tmp
  --cap-drop ALL
  --security-opt no-new-privileges
)

# --------------------------------------------------------------------------
step "build"
if [ "$build" -eq 1 ]; then
  if $docker build --tag "$image" "$root"; then
    ok "built $image"
  else
    bad "build failed"
    exit 1
  fi
else
  ok "reusing $image"
fi

# --------------------------------------------------------------------------
step "the image ships no deployment state, no source tree and no dev tooling"

# -xdev keeps this inside the image's own filesystem, and no volume is mounted,
# so anything found here came out of a layer.
# `resources` is excluded under /usr/local because the standard library has an
# importlib/resources of its own; what this is looking for is the 844 MB of
# upstream checkouts, which could only ever land in /app.
found=$($docker run --rm --entrypoint sh "$image" -c '
  find / -xdev \( \
       -name "fxa.toml" \
    -o -name "*.sqlite" -o -name "*.sqlite-wal" -o -name "*.sqlite-shm" \
    -o -name "signing-key.json" -o -name "retired-key.json" \
    -o -name ".git" \
    -o \( -name "resources" -not -path "/usr/local/*" \) \
  \) -print 2>/dev/null')
if [ -z "$found" ]; then
  ok "no fxa.toml, database, signing key, .git or resources/ in any layer"
else
  bad "the image contains: $(tr '\n' ' ' <<<"$found")"
fi

# --no-editable is what makes this true: the project is installed into the venv,
# so /app needs no source tree, and there is nothing to leak from one.
listing=$($docker run --rm --entrypoint sh "$image" -c 'ls -A /app')
if [ "$listing" = ".venv" ]; then
  ok "/app holds .venv and nothing else"
else
  bad "/app holds: $(tr '\n' ' ' <<<"$listing")"
fi

# --no-dev.  pytest in a deployed image is dead weight and extra attack surface.
if $docker run --rm --entrypoint python "$image" -c 'import pytest' >/dev/null 2>&1; then
  bad "pytest is installed in the runtime image (--no-dev did not take)"
else
  ok "dev dependencies absent"
fi

if $docker run --rm --entrypoint sh "$image" -c 'command -v uv' >/dev/null 2>&1; then
  bad "uv is present in the runtime stage"
else
  ok "no build tooling in the runtime stage"
fi

# --------------------------------------------------------------------------
step "a missing signing key stays a loud failure"

# No entrypoint script mints one.  A container that silently generates a key
# after a volume fails to mount looks like it recovered, while having
# invalidated every outstanding token.
$docker volume create "$empty_volume" >/dev/null
$docker run --rm -v "$empty_volume:/data" "${harden[@]}" --entrypoint sh "$image" \
  -c "printf 'public_url = \"%s\"\n' '$public_url' > /data/fxa.toml"
output=$($docker run --rm -v "$empty_volume:/data" "${harden[@]}" "$image" serve 2>&1)
status=$?
if [ "$status" -ne 0 ]; then
  ok "serve without a key exits $status"
else
  bad "serve started with no signing key"
fi
expect_contains "and says which command to run" "$output" "run \`fxa-lite keygen\` first"

# --------------------------------------------------------------------------
step "bootstrap: config, keygen, account add"

$docker volume create "$volume" >/dev/null

# The whole configuration surface: one file in the volume.  config.py resolves
# relative paths against the directory holding it, so the database and the key
# land beside it without a flag.
$docker run --rm --interactive -v "$volume:/data" "${harden[@]}" \
  --entrypoint sh "$image" -c "cat > /data/fxa.toml" <<EOF
public_url = "$public_url"
EOF

output=$($docker run --rm -v "$volume:/data" "${harden[@]}" "$image" keygen 2>&1)
expect_contains "keygen writes the key" "$output" "signing key written to /data/signing-key.json"

# 0600 *and* owned by the uid serve runs as — either half alone proves nothing.
modes=$($docker run --rm -v "$volume:/data" --entrypoint sh "$image" \
  -c 'stat -c "%a %U %U" /data/signing-key.json')
if [ "$modes" = "600 fxa fxa" ]; then
  ok "signing key is 0600 and owned by the runtime user"
else
  bad "signing key is '$modes', want '600 fxa fxa'"
fi

output=$($docker run --rm -v "$volume:/data" "${harden[@]}" "$image" \
  account add "$email" --password "$password" 2>&1)
expect_contains "account add creates the account" "$output" "created $email"

output=$($docker run --rm -v "$volume:/data" "${harden[@]}" "$image" account list 2>&1)
expect_contains "account list finds it" "$output" "$email"

# The database must not be readable by anyone else either — it holds kA in the
# clear and session token ids that are themselves the credential.  AUDIT.md's F5:
# sqlite3.connect used the umask and landed 0644, and `db._restrict` now narrows
# it on every connect, before the WAL pragma so the sidecars inherit the mode.
modes=$($docker run --rm -v "$volume:/data" --entrypoint sh "$image" \
  -c 'stat -c "%a %U" /data/fxa.sqlite')
case "$modes" in
  600\ fxa) ok "database is 0600 and owned by the runtime user" ;;
  *\ fxa) bad "database is '$modes', want '600 fxa' — AUDIT.md F5 has regressed" ;;
  *) bad "database is '$modes': wrong owner, so /data ownership is broken" ;;
esac

# --------------------------------------------------------------------------
step "serve"

$docker rm --force "$container" >/dev/null 2>&1
$docker run --detach --name "$container" \
  -v "$volume:/data" "${harden[@]}" \
  --publish "127.0.0.1:$port:9000" \
  "$image" >/dev/null || bad "could not start the container"

base=http://127.0.0.1:$port
for _ in $(seq 40); do
  curl -fsS "$base/__lbheartbeat__" >/dev/null 2>&1 && break
  sleep 0.5
done

# /__heartbeat__ pings the database rather than merely answering, which is why
# it is what the HEALTHCHECK targets: it can tell a failed volume mount from a
# healthy process.
body=$(curl -fsS "$base/__heartbeat__" 2>&1)
if [ "$body" = "{}" ]; then
  ok "/__heartbeat__ answers {} — the database opened"
else
  bad "/__heartbeat__ said: $body"
  $docker logs "$container" 2>&1 | tail -20 >&2
fi

# The first thing a browser reads.  Every URL in it is built from public_url, so
# this also proves the container answers for the external origin rather than for
# whatever Host the request carried — which is what makes a reverse proxy work.
body=$(curl -fsS "$base/.well-known/fxa-client-configuration" 2>&1)
expect_contains "discovery names the external auth server" "$body" \
  "\"auth_server_base_url\":\"$public_url\""
expect_contains "discovery names the external tokenserver" "$body" \
  "\"sync_tokenserver_base_url\":\"$public_url/token\""
if [[ $body == *"127.0.0.1:$port"* ]]; then
  bad "discovery leaked the container's own origin"
else
  ok "discovery never mentions the container's origin"
fi

body=$(curl -fsS "$base/v1/jwks" 2>&1)
expect_contains "/v1/jwks serves the key keygen made" "$body" '"kty":"RSA"'

# --------------------------------------------------------------------------
step "compose and nginx configs parse"

if $docker compose -f "$root/docker-compose.yaml" config --quiet >/dev/null 2>&1; then
  ok "docker-compose.yaml is valid"
else
  bad "docker compose config rejected docker-compose.yaml"
fi

example=$root/deploy/nginx.conf.example
if [ -f "$example" ] && command -v openssl >/dev/null; then
  mkdir -p "$certs/live/fxa.example.com"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=fxa.example.com \
    -keyout "$certs/live/fxa.example.com/privkey.pem" \
    -out "$certs/live/fxa.example.com/fullchain.pem" >/dev/null 2>&1
  chmod -R a+rX "$certs"
  nginx_image=$(awk '/^ *image: nginx:/ { print $2; exit }' "$root/docker-compose.yaml")
  output=$($docker run --rm \
    -v "$example:/etc/nginx/conf.d/default.conf:ro" \
    -v "$certs:/etc/letsencrypt:ro" \
    "$nginx_image" nginx -t 2>&1)
  expect_contains "deploy/nginx.conf.example is valid nginx" "$output" "syntax is ok"
  # The limit the audit decided must ship uncommented, not merely be mentioned.
  if grep -Eq '^\s*limit_req_zone' "$example"; then
    ok "the rate limit ships uncommented"
  else
    bad "limit_req_zone is missing or commented out in $example"
  fi
else
  printf '  skip  nginx check (no %s, or no openssl)\n' "$example"
fi

# --------------------------------------------------------------------------
if [ "$failures" -eq 0 ]; then
  printf '\n\033[32mall checks passed\033[0m\n'
  exit 0
fi
printf '\n\033[31m%d check(s) failed\033[0m\n' "$failures" >&2
exit 1
