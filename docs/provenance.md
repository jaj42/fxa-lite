# Provenance and divergences

fxa-lite is a reimplementation, not a fork. Nothing here was copied; every
protocol constant and every "matches the reference" claim in the source was read
out of a checkout, and this chapter is where those two facts are made
checkable — what was read, and where the result deliberately differs from it.

## What "the reference" means

`UPSTREAM.toml` pins each checkout to the commit fxa-lite was read against, and
lists the paths that were actually read — not the repository. `mozilla/fxa` is a
monorepo whose churn is overwhelmingly subscriptions, Glean and the settings
SPA, none of which are implemented here; the point of the path list is that
`scripts/upstream-diff.sh` shows a protocol change as a handful of commits
instead of two thousand irrelevant ones.

A pin is bumped only together with the code change, or the note, that answers
its diff. The file then always means "fxa-lite is current with respect to this
commit", never "this is where we last happened to look".

`tests/test_upstream.py` asserts every path below still exists in its checkout,
and skips when `resources/` is absent. Upstream renames files, and a stale path
makes the diff **empty** — which reads as "nothing changed", the one failure
mode this file cannot survive.

```{upstream-table}
```

## Divergences

Everything below is generated from `# DIVERGENCE:` markers in the source. There
is no authored copy of this list: the marker sits at the code that does the
diverging, and `tests/test_divergences.py` is what keeps the set of markers and
the set of behaviours in step. A divergence that stops being one is documented
as gone by deleting its marker.

Each entry says what upstream does, what fxa-lite does instead, why, and what it
takes away — because the fourth of those is the one a divergence list usually
omits.

:::{note}
This chapter is public, so it is written as reasoning rather than as a map. Two
kinds of thing are deliberately not here: the operator-dependent controls, which
are instructions on [Running it](running.md) rather than a list of what is
missing, and any exploitation path. `AUDIT.md` in the repository is the
phase-10 findings list, and the README's **Security** section is what an
operator has to know.
:::

```{divergence-table}
```

## The shape of the list

Read together, those markers fall into four groups, and it is worth naming them
because the groups have different risk:

**Stricter than upstream** — scope validation, the tokenserver's `aud` check,
the Sync payload hash. Each is a check upstream skips for a reason that does not
apply here: an admin panel it has and this does not, an ecosystem of relying
parties it must not break, a client population it cannot re-derive. The risk in
this group is interoperability, and it is what the conformance client and the
real-Firefox runs are for.

**Features that are off, answered in the protocol's own words** — the command
queue, the push fan-out, registration. The temptation in each case was a 200
that promises something impossible; the answer instead is upstream's own
`featureNotEnabled`, 403 with errno 202, which is a value the client's error
table already contains. The risk here is a client that reads the 403 as fatal
rather than as absent, which is why none of them carries `retryAfter`.

**Consequences of being one process** — the derived tokenserver secret, the real
foreign key on Sync users, `/` belonging to the content server. These are not
choices so much as things that stopped being problems, and the cost of each is
that the tiers can no longer be separated without a migration.

**Upstream bugs not reproduced** — `do_append`'s missing id filter, batches
surviving a storage wipe. The rule applied was: reproduce upstream's behaviour
wherever a client might depend on it, and refuse only where depending on it
would mean depending on data loss.

## Checking any of it yourself

```sh
scripts/upstream-diff.sh          # what upstream did to those paths since the pin
uv run pytest tests/test_upstream.py
uv run pytest tests/test_divergences.py
```

The first is not a pass/fail on the code. It is the question the code cannot ask
itself: has upstream changed one of the files a constant was read from? Run it
before bumping a pin, and bump the pin only with the change, or the note, that
answers its diff.
