# Provenance and divergences

fxa-lite is a reimplementation, not a fork. Nothing here was copied; every
protocol constant and every "matches the reference" claim in the source was read
out of a checkout, and this chapter is where those two facts are made
checkable — what was read, and where the result deliberately differs from it.

## What "the reference" means

`UPSTREAM.toml` pins each checkout to the commit fxa-lite was read against. It
holds two kinds of entry, and the difference is what is being promised.

**Tracked** — `[[repo]]`, and there are exactly two of them: `mozilla/fxa` and
`mozilla-services/syncstorage-rs`. These are the functionality fxa-lite
replicates, so they carry the paths that were actually read rather than the
repository. `mozilla/fxa` is a monorepo whose churn is overwhelmingly
subscriptions, Glean and the settings SPA, none of which are implemented here;
the point of the path list is that `scripts/upstream-diff.sh` shows a protocol
change as a handful of commits instead of two thousand irrelevant ones. A pin
is bumped only together with the code change, or the note, that answers its
diff, so the entry always means "fxa-lite is current with respect to this
commit" and never "this is where we last happened to look".

**Cited** — `[[reference]]`, everything else. Most of these are the *other side
of the wire*: the Rust `fxa-client` crate every mobile build embeds, Fenix's
Kotlin, Desktop's account client. fxa-lite does not implement them and has
nothing to stay current with, so they are pinned for one purpose only — a claim
about what a client requires is a claim about a specific commit, and this is
where that commit is written down. They carry no path list and
`upstream-diff.sh` does not follow them. What each one actually supports is
written at the claim — `BUGS.md` in the repository, or [Pointing a browser at
it](clients.md) — which is the only place a reader can check it.

`tests/test_upstream.py` holds both halves in place. Every tracked path still
exists in its checkout, because upstream renames files and a stale path makes
the diff **empty** — which reads as "nothing changed", the one failure mode
this file cannot survive. Every pin of either kind still resolves, because a
citation to a commit that is not there is not a citation. And every checkout
under `resources/` appears as one kind or the other: narrowing what is *tracked*
to two repositories did not narrow what is *recorded*, and a clone that is
neither is something somebody read and did not write down. All of it skips when
`resources/` is absent.

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

**Features that are off** — the command queue, the push fan-out, registration.
The temptation in each case was a 200 that promises something impossible, and
for two of the three the answer is upstream's own `featureNotEnabled`, 403 with
errno 202, none of them carrying `retryAfter`.

The named risk in this group was "a client that reads the 403 as fatal rather
than as absent", and it happened. Firefox for Android polls the command queue,
and the 403 crashed it: the Rust `fxa-client` maps every 403 to
`FxaError::Forbidden` without reading errno at all, android-components'
`shouldPropagate` allow-lists the exceptions it treats as recoverable and ends
`else -> true`, and `Forbidden` is not on the list — so the poll rethrows out of
the coroutine behind Fenix's *Sync now* button. The queue now answers the
empty-queue document instead, which upstream's own `PushboxDB.retrieve` computes
for a pushbox with nothing in it.

The lesson is narrower than "do not use 403". errno 202 really is in the
client's error table — the *JavaScript* client's. `/account/devices/notify`
keeps the same 403 for the same feature, because the check that matters is not
what the error table says but which client asks: `fxa-client`'s HTTP surface
never posts to that route. "Answered in the protocol's own words" is a claim
about a reader, so it has to name one.

**Consequences of being one process** — the derived tokenserver secret, the real
foreign key on Sync users, `/` belonging to the content server. These are not
choices so much as things that stopped being problems, and the cost of each is
that the tiers can no longer be separated without a migration.

**Upstream bugs not reproduced** — `do_append`'s missing id filter, batches
surviving a storage wipe. The rule applied was: reproduce upstream's behaviour
wherever a client might depend on it, and refuse only where depending on it
would mean depending on data loss.

Those two are the only ones that turned into divergences, because they are the
only ones whose fix belongs in *this* server. They are not the only ones found:
`BUGS.md` in the repository is the full list — sixteen defects and risky
defaults across `mozilla/fxa`, `syncstorage-rs`, `application-services` and
Fenix, each re-read at the commit `UPSTREAM.toml` pins before it was written
down. Most of them are not actionable here at all, which is exactly why they
needed somewhere to live that is not a divergence list.

## Licensing

fxa-lite is **MPL-2.0**, and that is a conclusion rather than a preference. The
premises are in the table above.

Every project fxa-lite took something from is MPL-2.0 — `mozilla/fxa`,
`syncstorage-rs`, `application-services`, `mozilla-firefox/firefox`,
`firefox-android` and `fxa-selfhosting`. The projects under terms that would
have constrained harder had nothing taken from them, and that is the point of
those `took = "nothing"` lines rather than a pedantic flourish: IronFox is
AGPL-3.0, `jwcrypto` is LGPL-3.0, and `michielbdejong/fxa-self-hosting` has no
LICENSE file at all, so it is all-rights-reserved. `python-jose` (MIT) and
`joserfc` (BSD-3-Clause) were likewise evaluated and not adopted.
`tests/test_license.py` asserts exactly that split, so an entry added under
harder terms that *does* contribute something fails the suite rather than
quietly changing what this page can claim.

### Why not something more permissive

fxa-lite is a reimplementation, but it is not *only* one, and MIT was never
actually available. MPL-2.0 is file-level copyleft: §1.10 defines a Modification
as, among other things, any file of Covered Software that has been changed, and
§3.1 keeps such a file under the licence. Several files here are ports and
transcriptions of MPL-2.0 source rather than independent work —

- `oauth/scopes.py`, a port of `fxa-shared/oauth/scopes.ts`, precomputed
  implicants and iteration order included;
- `auth/attached_clients.py`, a transcription of `ConnectedServicesFactory`,
  with that module's own spec fixture as its known-answer test;
- `content/assets/crypto.js` and `webchannel.js`, ports of
  `fxa-auth-client/lib/crypto.ts` and `fxa-settings`'s WebChannel;
- `tokenserver/tokenlib.py`, from `tokenserver-auth/src/token/native.rs`;
- `auth/models.py`'s transcribed `isValidEmailAddress`;
- `profile/__init__.py`'s monogram avatar, from the reference's own SVG route;
- `oauth/clients.py`'s `deviceManagementClientIds`, copied verbatim because it
  is an authorization rule and trimming it would silently change it;
- `tests/vectors/*.json` and `tests/conformance/client.py`.

A split licence — MPL on those, MIT on the independently written majority — is
legally available for exactly the same reason, and is deliberately not taken. It
would mean maintaining a per-file map, and answering "which side is this file
on?" at every future edit, in exchange for a permissiveness that MPL-2.0 §3.3
mostly already grants: a recipient may distribute a Larger Work under terms of
their choosing provided the Covered Software files stay under this licence. The
cost of choosing MPL over MIT is therefore small and the cost of the map is not.

Nothing in the dependency set constrains the choice either way: `fastapi` is
MIT, `uvicorn` BSD-3-Clause, and `cryptography` is Apache-2.0 OR BSD-3-Clause.

### What this means in practice

Every first-party source file carries the Exhibit A notice, uniformly rather
than only on the derived ones — a list of which files are Modifications is a
thing that rots, and the notice costs three lines.
`tests/test_license.py` keeps all of it in step: the LICENSE text, the PEP 639
metadata in `pyproject.toml`, the notice on every source file (and below any
shebang, since a notice above `#!` silently stops a script being executable),
and the premise about upstream licences above.

If fxa-lite is ever relicensed or dual-licensed, the ported files are the
constraint, and the list above plus `UPSTREAM.toml` is the record of which they
are.

:::{note}
This is a reading of the licences and of this codebase, not legal advice.
:::

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
