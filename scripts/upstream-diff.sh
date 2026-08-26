#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# What has upstream done to the parts of it we implement, since we last looked?
#
# For every `[[repo]]` in UPSTREAM.toml, log the commits between the pinned commit and the
# current remote head that touch one of the paths we actually read.  A log, not a diff: a
# protocol change shows up as a commit touching `lib/crypto/`, and a thousand subscription
# commits show up as nothing at all.
#
# Only the tracked half of the manifest is followed.  `[[reference]]` entries are pinned so a
# claim can cite a commit — mostly the client on the other side of the wire — and fxa-lite does
# not replicate them, so there is nothing to stay current with and no diff to take.  Naming one
# on the command line says so rather than pretending it does not exist.
#
# Usage:  scripts/upstream-diff.sh [--no-fetch] [repo ...]
#
# Fetches first by default — comparing against a stale remote-tracking ref answers the wrong
# question.  Pass --no-fetch to work offline, or repo directory names to narrow the run.
#
# Exit status is 1 if any entry has commits to show, so CI can ask "is fxa-lite current?" and
# get an answer, and 2 if an entry could not be read at all.  A missing checkout is neither:
# `resources/` is gitignored, and not every machine needs six hundred megabytes of Node
# monorepo cloned to be useful.

set -uo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$root/UPSTREAM.toml"
resources="$root/resources"

fetch=1
wanted=()
for arg in "$@"; do
  case "$arg" in
    --no-fetch) fetch=0 ;;
    -h | --help)
      awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    -*)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
    *) wanted+=("$arg") ;;
  esac
done

# TOML in, tab-separated shell food out.  The manifest is the single source of truth for the
# path lists; re-typing them here is how the two drift apart.  References come out first and
# tagged, because the only thing this script does with one is explain why it is not following
# it — an argument naming a reference is a fair question with a specific answer, not a typo.
all=$(python3 - "$manifest" <<'PY'
import sys, tomllib

with open(sys.argv[1], "rb") as fh:
    manifest = tomllib.load(fh)

for entry in manifest.get("reference", []):
    print("\t".join(["#ref", entry["dir"]]))
for repo in manifest["repo"]:
    print("\t".join([repo["dir"], repo["branch"], repo["commit"], *repo["paths"]]))
PY
) || exit 2

references=$(grep '^#ref' <<<"$all" | cut -f2)
entries=$(grep -v '^#ref' <<<"$all")

# A name that matches no entry is a typo, and silently logging nothing is how a typo goes
# unnoticed until someone concludes the repository is current.
for name in ${wanted[@]+"${wanted[@]}"}; do
  cut -f1 <<<"$entries" | grep -qxF "$name" && continue
  if grep -qxF "$name" <<<"$references"; then
    printf "%s is a [[reference]] in UPSTREAM.toml — pinned so a claim can cite a commit,\n" "$name" >&2
    printf "not tracked for change, so there is no diff to take.  What it supports is written\n" >&2
    printf "at the claim, in BUGS.md or under docs/.\n" >&2
    printf "Tracked: %s\n" "$(cut -f1 <<<"$entries" | tr '\n' ' ')" >&2
    exit 2
  fi
  echo "no entry named '$name' in UPSTREAM.toml" >&2
  exit 2
done

behind=0
broken=0

while IFS=$'\t' read -r dir branch commit paths; do
  if [ ${#wanted[@]} -gt 0 ] && [[ ! " ${wanted[*]} " == *" $dir "* ]]; then
    continue
  fi

  checkout="$resources/$dir"
  if [ ! -d "$checkout/.git" ]; then
    printf '%s: no checkout at resources/%s — skipped\n' "$dir" "$dir"
    continue
  fi

  if [ "$fetch" -eq 1 ] && ! git -C "$checkout" fetch --quiet origin "$branch"; then
    printf '%s: fetch failed — reporting against the remote-tracking ref as it stands\n' "$dir" >&2
  fi

  IFS=$'\t' read -r -a path_list <<<"$paths"
  log=$(git -C "$checkout" log --oneline --no-decorate \
    "$commit..origin/$branch" -- "${path_list[@]}" 2>&1) || {
    printf '%s: %s\n' "$dir" "$log" >&2
    broken=1
    continue
  }

  printf '\n=== %s  %s..origin/%s ===\n' "$dir" "${commit:0:8}" "$branch"
  if [ -z "$log" ]; then
    printf 'current\n'
  else
    printf '%s\n' "$log"
    printf -- '-- %s commit(s) touching paths we implement\n' "$(printf '%s\n' "$log" | wc -l | tr -d ' ')"
    behind=1
  fi
done <<<"$entries"

[ "$broken" -eq 1 ] && exit 2
[ "$behind" -eq 1 ] && exit 1
exit 0
