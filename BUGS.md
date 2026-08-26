# Upstream defects found while reimplementing

`AUDIT.md` is fxa-lite's own findings list. This is the one pointing the other way.

Reimplementing a protocol from its reference means reading the reference closely enough to
reproduce it byte for byte, which is a different and more suspicious kind of reading than
maintaining it. Sixteen things turned up that way across four Mozilla codebases, and until
now each lived as a sentence in `plan.md` or a comment beside the route that works around it.
This file collects them so any one can be lifted into the relevant tracker unedited.

**Every claim here was re-read at the commit `UPSTREAM.toml` pins**, not at whatever the
local checkout happened to have; the pins are named per section and the symbols are quoted.
One finding was dropped in that pass because it did not survive it — see *Checked and
withdrawn* at the end, which is there so the list reads as an argument rather than as a
grievance.

**Still current as of 2026-08-26.** `scripts/upstream-diff.sh` reports five commits since the
two tracked pins, and none of them touches a file named below: the `syncstorage-rs` one
(`6417c0be`, batch-commit transaction tagging) is Spanner and reconciler tooling with no change
under `syncstorage-mysql/`, and none of the four `mozilla/fxa` commits touches `app-error.ts`,
`hawk-fxa-token.js`, `devices-and-sessions.js` or `oauth/grant.js`. The pins are not bumped
here — that is a separate change, made together with whatever answers its diff — but the check
is cheap and a bug report for something already fixed is worse than no bug report.

## Two tiers

**Defect** — wrong by upstream's own standard: data corrupted, deleted records resurrected,
an app crashed, a client stalled, a check that does not check the thing it is named for.

**Risky default** — deliberate upstream, documented, and arguably wrong anyway. These are
configuration and design choices, not mistakes, and they are labelled so that the list is not
overclaiming. Four of the sixteen are in this tier and each one quotes the upstream comment
that explains the choice.

## Scope and disclosure

Four findings are security-relevant (SS-3, SS-4, FXA-3, FXA-4). They are written as mechanism
and consequence, in the register `AUDIT.md` uses, and not as exploitation paths. Nothing here
is a novel attack against a running Mozilla service; these are properties of published source,
three of them carrying upstream's own explanatory comment. Anything that did turn out to be
exploitable against production would belong in a report to Mozilla and not in a public file in
somebody's repository.

fxa-lite is one household's server. It does not run at Mozilla's scale, it does not have
Mozilla's client population to avoid breaking, and several of the defaults called risky below
are risky *here* precisely because they were reasonable *there*. Where fxa-lite decided
differently, the decision has a `# DIVERGENCE:` marker at the code and is published in
[Provenance and divergences](https://jaj42.github.io/fxa-lite/provenance.html); this file
links to those slugs rather than restating them.

---

# mozilla-services/syncstorage-rs

Pinned at `3f0f985cc92a72647a3a701da702a3d5f28d05df` (2026-08-21), MPL-2.0.

## SS-1 — `do_append` stages batch items without filtering on the BSO id

**Tier** — Defect: silent data corruption, MySQL backend only.

**Where** — `syncstorage-mysql/src/db/batch_impl.rs:302-318`.

**What happens.** When a batched upload re-sends a record that is already staged, `do_append`
takes the update branch:

```rust
diesel::update(
    batch_upload_items::table
        .filter(batch_upload_items::user_id.eq(user_id.legacy_id as i64))
        .filter(batch_upload_items::batch_id.eq(batch_id)),
)
.set(&UpdateBatches { payload, payload_size, ttl_offset })
```

The filter is `(user_id, batch_id)`. The BSO id is absent, so the statement rewrites the
`payload`, `payload_size` and `ttl_offset` of **every record already staged in that batch**
with the incoming record's values.

The id is not merely available, it is the thing the code just finished computing: the
`existing` set is keyed on `exist_idx(user_id, batch_id, bso_id)` twenty lines above, and the
table's own primary key is declared `batch_upload_items (batch_id, user_id, id)` in
`schema.rs:13`. The one-line fix is a third `.filter(batch_upload_items::id.eq(&bso.id))`.

**Why it matters.** Batching exists for large uploads, so this corrupts exactly the case it was
built for. It is silent on both sides: the POST succeeds, the commit succeeds, and the client
reads back a collection in which N records share one payload. For an encrypted collection the
payloads then fail to decrypt against the records the client thinks it wrote, or worse, decrypt
into another record's contents.

**The other two backends get it right**, which is the strongest evidence that this is a slip
rather than an intention. Postgres uses `ON CONFLICT (user_id, collection_id, batch_id,
batch_bso_id) DO UPDATE` (`syncstorage-postgres/src/db/batch_impl.rs`), and Spanner writes a
keyed mutation whose key includes `batch_bso_id`. Only MySQL — the backend Firefox Sync runs
on — omits the id.

**A second, smaller bug in the same statement.** `UpdateBatches` has fields for `payload`,
`payload_size` and `ttl_offset` and none for `sortindex`, so a re-staged record silently keeps
the sortindex it was first staged with. The insert branch does set it.

**Reproduction.** Open a batch on a MySQL-backed instance; POST records `a` and `b` with
distinct payloads; POST record `a` again with a third payload; commit. `b` comes back carrying
`a`'s second payload.

**fxa-lite** — `syncstorage/store.py:append_to_batch`, upsert keyed on `(uid, batch_id, id)`.
DIVERGENCE `batch-append-filters-id`.

## SS-2 — a storage wipe leaves open batches behind, so a later commit resurrects the deleted records

**Tier** — Defect: deleted data returns.

**Where** — `syncstorage-mysql/src/db/db_impl.rs:145-158` (`delete_storage`), against
`batch_impl.rs:181-218` (`commit_batch`).

**What happens.** `delete_storage` deletes from exactly two tables:

```rust
delete(bso::table).filter(bso::user_id.eq(user_id))
delete(user_collections::table).filter(user_collections::user_id.eq(user_id))
```

`batch_uploads` and `batch_upload_items` are untouched. A batch opened before the wipe is
therefore still open after it, still passes `validate_batch`, and `commit_batch` will happily
run `batch_commit.sql` — which `INSERT`s straight from `batch_upload_items` back into `bso`.
Every record staged before the wipe is restored, stamped with a fresh `modified`.

`delete_collection` has the same gap for one collection.

**Why it matters.** `DELETE /1.5/{uid}` is not a convenience; Firefox issues it when it has
decided the server's contents must not come back — a key rotation, a "disconnect and wipe", a
`crypto/keys` mismatch. A delete that can be undone by a request already in flight is not the
operation the route's name promises, and the window is exactly the case where a client is
uploading a lot and therefore batching.

**Reproduction.** Open a batch, stage records, `DELETE /1.5/{uid}`, then commit the batch id.
The records are back.

**fxa-lite** — `syncstorage/store.py:delete_storage` deletes the account's open batches and
their items. DIVERGENCE `wipe-clears-open-batches`.

## SS-3 — the HAWK payload hash is never verified, so request bodies are unauthenticated

**Tier** — Defect (security).

**Where** — `syncserver/src/web/auth.rs:63-123` (`HawkPayload::new`).

**What happens.** The signature is checked like this:

```rust
let request = RequestBuilder::new(method, host, port, path).request();
...
request.validate_header(&header, &Key::new(token_secret.as_bytes(), Sha256)?, duration)
```

`HawkPayload::new` receives `method`, `path`, `host` and `port`. It never receives the request
body, so it cannot compare the `hash=` attribute the client sent against the body that arrived,
and `RequestBuilder` is never given a hash to compare with. The attribute is parsed, is covered
by the MAC as a *claim*, and is then never checked against anything.

**Why it matters.** HAWK's payload hash is the only thing that binds a body to a signature. A
client that computes one correctly — which is every correct HAWK client — is nonetheless served
by a server that has not checked it, so on any path where the ciphertext can be substituted the
MAC still verifies. TLS covers this in practice, which is why it has never bitten; the point is
that the guarantee the protocol offers is not the guarantee being provided, and a reader of the
code cannot tell.

**A related property in the same function.** The permitted clock skew is
`TimeDelta::weeks(52)` — one year — with the comment "Allow plenty of leeway for clock skew,
because client timestamps tend to be all over the shop", and there is no nonce cache. A
captured signed request is therefore replayable for a year. That is a deliberate and documented
trade and fxa-lite makes the same one; it is recorded here because it is what an unverified
payload hash compounds with.

**fxa-lite** — `syncstorage/hawk.py` verifies the hash when the client sends one, and serves a
request that omits it with the body uncovered, which is what the specification says. DIVERGENCE
`hawk-payload-hash-verified`; see also `AUDIT.md`, *Confirmed and pinned*, for why the hash
cannot simply be stripped.

## SS-4 — the tokenserver does not check `aud` on the access token

**Tier** — Risky default (security). Upstream's comment states the reasoning.

**Where** — `tokenserver-auth/src/crypto.rs:158-175`.

```rust
// The FxA OAuth ecosystem currently doesn't make good use of aud, and
// instead relies on scope for restricting which services can accept
// which tokens. So there's no value in checking it here, and in fact if
// we check it here, it fails because the right audience isn't being
// requested.
validation.validate_aud = false;
```

**What happens.** Audience validation is disabled for the OAuth access tokens the tokenserver
accepts. Authorization rests on scope alone.

**Why it matters.** `aud` is the claim that says which service a token was minted for. With it
off, any RS256 token from the trusted issuer bearing the `oldsync` scope is spendable at the
tokenserver regardless of who it was issued to, and the defence reduces to "no other relier is
granted that scope" — a property of the client registry rather than of the token.

The comment is honest about the cause: it is off because the ecosystem does not request the
right audience, not because checking is worthless. That makes it a compatibility ratchet, and
the same file shows the capability exists — `SETVerifierImpl::new`, sixty lines below, calls
`validation.set_audience(&[client_id])` for Security Event Tokens.

**fxa-lite** checks it, which is available only because it mints that audience itself in one
place. DIVERGENCE `tokenserver-audience-checked`.

## SS-5 — a batch-committed record with no TTL gets a fixed 2036 expiry, not "forever"

**Tier** — Defect: a wrong value, flagged `XXX` upstream, that expires real data on a fixed date.

**Where** — `syncstorage-mysql/src/db/batch_commit.sql:8` with `batch_impl.rs:196`, against
`db_impl.rs:220` and `:92`.

**What happens.** The commit SQL computes the expiry as
`COALESCE((ttl_offset * 1000) + ?, ?)`, and the two binds are:

```rust
.bind::<BigInt, _>(&timestamp.as_i64())      // now, for the offset case
.bind::<BigInt, _>((MAX_TTL as i64) * 1000)  // XXX:
```

When the staged item carries a TTL, the expiry is `now + ttl` — correct. When it does not, the
expiry is `MAX_TTL * 1000` with no `now` term: an absolute instant of 2 100 000 000 seconds
since the epoch, which is **July 2036**.

The un-batched path does it correctly. `put_bso` takes
`bso.ttl.map_or(DEFAULT_BSO_TTL, |ttl| ttl)` and binds
`timestamp + (i64::from(ttl) * 1000)` — a duration from now, with `DEFAULT_BSO_TTL` also
2 100 000 000, giving roughly the year 2092.

So the same record, written with no TTL, expires 56 years earlier if it went through a batch.
The upstream source marks the bind `// XXX:`, so the line was already suspected.

**Why it matters.** Two things. The expiry is readable by the client, so "forever" has two
observable spellings depending on a transport detail the client chose for unrelated reasons.
And July 2036 is a real date: every batch-written record with no explicit TTL on every Sync
account expires at the same instant. The constant was plainly meant as a duration.

**fxa-lite** reproduces this rather than tidying it, because a client can read the value back,
and the reproduction is commented at `syncstorage/store.py:commit_batch`. It is *not* marked as
a divergence, because it is parity.

## SS-6 — a collection read is truncated at 10 000 records, and the signal is a header the Rust client never reads

**Tier** — Defect: silent, partial reads. Joint with AS-3; neither half alone causes it.

**Where** — `syncstorage-mysql/src/db/db_impl.rs:29`, `:342`, `:425`;
`syncstorage-settings/src/lib.rs:21,27`.

**What happens.** A collection GET with no `limit` still gets one:

```rust
static DEFAULT_LIMIT: u32 = DEFAULT_MAX_TOTAL_RECORDS;   // 100 * 100 = 10_000
... .unwrap_or(DEFAULT_LIMIT as i64)
```

The server signals the truncation in `X-Weave-Next-Offset`, as the protocol requires. That is
correct and unremarkable on its own. What makes it a defect is the other end: the Rust client
every Firefox mobile build embeds has no reader for that header and no way to send an offset
back (AS-3). So the server truncates, says so in a header nobody reads, and the client treats
the short list as the whole collection.

**Why it matters.** Neither side reports an error. For an account with more than 10 000
bookmarks or history records, the phone downloads a prefix and merges it as if it were
complete. For bookmarks a truncated tree is not merely incomplete but unmergeable — the merger
is reasoning about a structure whose parents may be missing.

**Why raising the cap is not the fix.** It moves the cliff. The fix is on the client side
(AS-3) or a hard error rather than a silent short read.

**fxa-lite** reproduces `DEFAULT_LIMIT` exactly, and deliberately does *not* mark it as a
divergence, because it is parity and the DIVERGENCE list means "fxa-lite decided differently".
The edge is written down at `syncstorage/store.py:get_bsos` instead.

---

# mozilla/fxa

Pinned at `f87b36d0b92435869d2419993b1b5176b322b871` (2026-08-24), MPL-2.0. The browser half of
FXA-1 is read from `mozilla-firefox/firefox` at `39532fe5a7a63cf58953e0ce2e2e264c94313b12`.

## FXA-1 — `featureNotEnabled` sends a `Retry-After` that disables the browser's entire account client

**Tier** — Defect: a per-feature error takes down every unrelated request.

**Where** — `libs/accounts/errors/src/app-error.ts:599-617`, against
`services/common/hawkclient.sys.mjs:120-127` and
`services/fxaccounts/FxAccountsClient.sys.mjs:781-805`.

**What happens.** The server side:

```ts
static featureNotEnabled(retryAfter?: number) {
  if (!retryAfter) { retryAfter = 30; }
  return new AppError(
    { code: 403, error: 'Feature not enabled', errno: ERRNO.FEATURE_NOT_ENABLED, ... },
    { retryAfter: retryAfter },
    { 'retry-after': retryAfter.toString() }
  );
}
```

Every call site — nine of them across `routes/devices-and-sessions.js` and `pushbox/index.ts` —
passes no argument, so every one sends `retry-after: 30`.

The browser side then does this. `hawkclient.sys.mjs:_constructError` reads `retry-after` off
**any** response regardless of status and sets `errorObj.retryAfter`. `FxAccountsClient` catches
that and caches it:

```js
if (error.retryAfter) {
  this.backoffError = error;
  CommonUtils.namedTimer(this._clearBackoff, error.retryAfter * 1000, this, "fxaBackoffTimer");
}
```

and the *first statement* of `_requestWithHeaders` is:

```js
if (this.backoffError) {
  log.debug("Received new request during backoff, re-rejecting.");
  throw this.backoffError;
}
```

**Why it matters.** `backoffError` is a property of the client object, not of the route that
set it. For the 30 seconds after any `featureNotEnabled`, *every* FxA request — device list,
profile fetch, key fetch, token refresh, sign-in — is rejected inside the browser without a
packet being sent, and it is rejected with an error saying a feature is not enabled, which is
untrue of all of them.

The backoff protocol exists so a struggling server can shed load. `featureNotEnabled` is not
that: it describes a permanent deployment property, and no amount of waiting changes it. A
deployment that turns a feature off therefore pays a 30-second blackout of its whole account
API every time a client asks — and if anything polls the disabled route faster than every 30
seconds, the blackout never lifts.

**The fix is one line**: `featureNotEnabled` should not default `retryAfter`, and should send
neither the `info` field nor the header, because there is nothing to retry.

**fxa-lite** raises errno 202 with no `retryAfter` at all, with the reasoning at the factory
rather than at the call site. DIVERGENCE `no-retry-after-on-permanent-403`.

## FXA-2 — `deviceCommandsEnabled` also disables the device *list*

**Tier** — Risky default. Upstream's comment states the reasoning; the reasoning is the part
being disputed.

**Where** — `packages/fxa-auth-server/lib/routes/devices-and-sessions.js:249`, `:357`, `:639`.

**What happens.** The flag gates three routes for refresh-token callers:
`GET /account/device/commands`, `POST /account/devices/invoke_command` — and
`GET /account/devices`, with this comment:

```js
// The only reason a device calls this endpoint is to get a list of other devices
// it can send commands to, so feature-flag it as part of that feature.
if (config.oauth.deviceCommandsEnabled === false && credentials.refreshTokenId) {
  throw error.featureNotEnabled();
}
```

**Why it matters.** The premise is not true. A mobile client reads its device list to render
"signed in on N devices", to offer disconnecting one, and to populate connected-services UI —
all of which are meaningful with no command feature at all. A flag named for commands turning
off an unrelated read is a surprise for any deployment that sets it, and the surprise is
scoped to refresh-token callers, meaning it hits mobile and spares desktop.

**And it compounds.** The 403 it raises is FXA-1's, so it carries `retry-after: 30`; on Android
it is AS-2's opaque `Forbidden`, which is FA-1's crash. See *How four of these compound* below.

**fxa-lite** keeps `/account/devices` answering, and gates only the queue. DIVERGENCE
`device-commands-always-empty`.

## FXA-3 — `strictScopeValidation` is off by default, so a trusted client is granted scopes it is not registered for

**Tier** — Risky default (security).

**Where** — `packages/fxa-auth-server/config/index.ts:1746-1751` (`default: false`) and
`packages/fxa-auth-server/lib/oauth/grant.js:140-156`.

**What happens.**

```js
const invalidScopes = requestedGrant.scope.difference(trustedClientAllowedScopes);
if (!invalidScopes.isEmpty()) {
  if (config.get('oauthServer.strictScopeValidation')) {
    requestedGrant.scope = requestedGrant.scope.difference(invalidScopes);
  }
}
```

With the default `false`, the inner `if` is the whole body — so when a trusted client asks for
a scope outside `client.allowedScopes ∪ TRUSTED_CLIENT_ALLOWED_SCOPES`, the code computes the
set of invalid scopes, checks whether it is non-empty, and then does **nothing**. The scope is
granted.

**The honest bound on this finding.** Custom scopes — anything beginning `https` — are
validated unconditionally twenty lines below and throw `invalidScopes`. So the key-bearing
scopes cannot be smuggled: `https://identity.mozilla.com/apps/oldsync` is refused whatever this
flag says. What is grantable is the short scope namespace — `profile`, `openid`, `email`,
`basket` and any other bare name — to a trusted client whose registration does not list it.
That is a smaller hole than the flag's name suggests, and it is still a registry that does not
mean what it says.

**Why the default is defensible upstream and not here.** Upstream the client registry is a
MySQL table behind a staffed admin panel, and tightening the check would break relying parties
whose registrations have drifted. fxa-lite has three built-in clients and a config file.

**fxa-lite** runs the strict behaviour: an unregistered scope is dropped, not granted.
DIVERGENCE `strict-scope-validation`.

## FXA-4 — the accounts API parses HAWK signatures and discards them

**Tier** — Risky default (security). Deliberate, documented, and transitional.

**Where** — `packages/fxa-auth-server/lib/routes/auth-schemes/hawk-fxa-token.js`.

**What happens.** `parseAuthorizationHeader` extracts `id`, `ts`, `nonce`, `hash`, `ext`, `mac`,
`app` and `dlg`. The strategy then uses exactly one of them:

```js
const parsedHeader = parseAuthorizationHeader(auth);
token = await getCredentialsFunc(parsedHeader.id);
```

`mac`, `ts` and `nonce` are never read. The payload hook says so outright: "Since we skip Hawk
header validation, we don't need to perform payload validation either".

**Why it matters.** The `Authorization: Hawk id="…"` header is a bearer credential wearing
HAWK's clothes. None of what HAWK is for — binding a request to its method, URL, timestamp and
body, and making a captured header useless after its nonce — applies. A captured header is
replayable indefinitely against any route.

**Why it is a default rather than a defect.** This is a deliberate migration step, and the file
says so: the strategy carries a `auth.strategy.used{scheme=hawk,kind=…}` statsd metric
described as tracking "the Hawk -> Bearer migration", and the sibling scheme accepts
`Bearer fxs_…` for the same credentials. The end state is Bearer over TLS, where the same
security properties hold and nothing pretends otherwise. The cost in the meantime is that the
wire format claims a guarantee the server does not provide, and any reimplementer who verifies
the MAC — the obvious reading of the header — is incompatible with the reference.

**fxa-lite** matches the reference exactly, and says why at the code. DIVERGENCE
`hawk-macs-unverified`; `tests/test_security.py` pins that a HAWK header grants no more than
the equivalent Bearer one.

---

# mozilla/application-services

Pinned at `7674e0cf977272c746eebee7c145c982e06cc6c4` (2026-08-25), MPL-2.0. This is the
`fxa-client` and `sync15` crate set that every Firefox mobile build embeds.

## AS-1 — `avatar` is a required `String`, so a profile document without it fails to parse entirely

**Tier** — Defect: total loss of a feature on an optional field.

**Where** — `components/fxa-client/src/internal/http_client.rs`, `struct ProfileResponse`;
`components/fxa-client/src/state_machine`.

**What happens.**

```rust
pub struct ProfileResponse {
    pub uid: String,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar: String,
    pub avatar_default: bool,
}
```

`display_name` is optional. `avatar` and `avatar_default` are not. A profile document that
omits `avatar` therefore fails serde deserialisation, and the client does not get a profile
with no picture — it gets **no profile at all**.

**Why it matters.** Two consequences, and the second is worse than the first.

The visible one is FA-2: with no profile, Fenix's sync store never learns the account exists
and the main menu offers *Sign in* while Sync is signed in and actively syncing.

The invisible one is the state machine. A failed `get_profile` in the `Connected` state is
`account.get_profile().to_state_machine_err(|| S::AuthIssues)?` — but a serde failure is not an
authentication error, so the one recovery attempt does not apply and the account lands in
`AuthIssues`. A working, syncing account reports authentication problems because a picture was
missing.

**Why it is a defect rather than a server requirement.** Nothing in the profile document's
definition makes `avatar` mandatory; the reference server always sends one only because it
always has one to send — `fxa-profile-server`'s `routes/profile.js:nextAvatar` synthesises a
monogram URL when the user has uploaded nothing. A client hard-failing on an absent optional
field is the fragility, and the one-word fix is `Option<String>`.

**Reproduction.** Serve a `GET /profile/v1/profile` response without the `avatar` key to any
Firefox for Android build. Sync works; the account is invisible to the app.

**fxa-lite** now always sends an avatar, reproducing the reference's monogram behaviour, because
the client is what it is. DIVERGENCE `avatar-is-always-a-monogram`.

## AS-2 — every 403 becomes `FxaError::Forbidden`, and `errno` is discarded

**Tier** — Defect: an unrecoverable classification for a recoverable condition.

**Where** — `components/fxa-client/src/error.rs:146-152` and `:222-224`.

**What happens.** The internal error carries the full FxA envelope:

```rust
RemoteError { code: u64, errno: u64, error: String, message: String, info: String },
```

and the mapping to the public error type reads only `code`:

```rust
Error::RemoteError { code: 403, .. } => {
    ErrorHandling::convert(FxaError::Forbidden).log_warning()
}
```

The `..` throws away an `errno` that was parsed and is sitting right there.

**Why it matters.** FxA distinguishes its 403s by errno, and the distinction is the whole point
of the field: errno 202 is `FEATURE_NOT_ENABLED` — "this deployment does not do that, ask about
something else" — while other 403s mean the caller is not allowed. To this client they are one
error, and it is the one that FA-1 treats as fatal.

The contrast in the same match is instructive: `_ => FxaError::Other(...)`. A **404** is
therefore *more* survivable than a 403, because it falls to the catch-all that
android-components treats as recoverable. That is the wrong way round, and it is what made a
server switching from 404 to 403 — a strictly more informative answer — a crash.

**fxa-lite** stopped raising 403 on the route mobile polls. DIVERGENCE
`device-commands-always-empty`.

## AS-3 — `sync15` cannot page a collection read

**Tier** — Defect: silent partial reads. Joint with SS-6.

**Where** — `components/sync15/src/engine/request.rs` (`struct CollectionRequest`) and
`components/sync15/src/client/sync.rs:50-58`.

**What happens.** The request type has no offset:

```rust
pub struct CollectionRequest {
    pub collection: CollectionName,
    pub full: bool,
    pub ids: Option<Vec<Guid>>,
    pub limit: Option<RequestLimit>,
    pub older: Option<ServerTimestamp>,
    pub newer: Option<ServerTimestamp>,
}
```

and `X-Weave-Next-Offset` appears exactly once in the entire crate — inside a comment:

```rust
// Ideally we would "batch" incoming records (eg, fetch just 1000 at a time)
// and ask the engine to "stage" them as they come in - but currently we just read
// them all in one request.
//
// Doing this batching will involve specifying a "limit=" param and
// "x-if-unmodified-since" for each request, looking for an
// "X-Weave-Next-Offset header in the response and using that in subsequent requests.
```

**Why it matters.** "We just read them all in one request" is only true up to the server's
`DEFAULT_LIMIT` of 10 000 (SS-6), above which the server returns a prefix plus an offset header
this crate has no reader for. There is no error on either side, so the engine merges a prefix
as though it were the collection.

**This is a known gap, and that is worth saying**: the comment describes the missing feature
accurately and even names the hard part (handling a 412 on a later page, so a timestamp cannot
be trusted until every page has been staged). What the comment does not connect is that the cap
already exists server-side, so the consequence today is not "we do not batch yet" but "accounts
past 10 000 records in a collection sync incorrectly and silently".

**fxa-lite** serves the header correctly and reproduces the cap; the gap is the client's. Noted
at `syncstorage/store.py:get_bsos`.

---

# mozilla-mobile/firefox-android

Pinned at `fe8a71cd70ad5674abe1824fe11dc78372b736c2` (2024-06-17), MPL-2.0.

**This repository was archived in June 2024.** Fenix and android-components now live in the
Firefox monorepo. It is pinned because the alternative is a claim about Kotlin with no checkout
behind it, and because the two files carrying the argument have held the same allow-list since
long before the archive. Anything filed from this section should be re-checked against
mozilla-central first; the symbol names below are the ones to search for.

## FA-1 — an unrecognised FxA error crashes the app, and `Forbidden` is unrecognised

**Tier** — Defect: force-close, reachable from a server response.

**Where** — `android-components/…/service/fxa/Exceptions.kt` (`shouldPropagate`),
`…/service/fxa/FxaDeviceConstellation.kt:219-222` (`pollForCommands`),
`fenix/app/src/main/java/org/mozilla/fenix/settings/account/AccountSettingsFragment.kt:339-351`
(`syncNow`).

**What happens.** `shouldPropagate()` is an allow-list of the errors treated as recoverable:

```kotlin
/**
 * @return 'true' if this exception should be re-thrown and eventually crash the app.
 */
fun FxaException.shouldPropagate(): Boolean {
    return when (this) {
        is FxaPanicException -> true
        is FxaNetworkException,
        is FxaUnauthorizedException,
        is FxaUnspecifiedException,
        is FxaOriginMismatchException,
        is FxaNoExistingAuthFlow,
        -> false
        // Throw on newly encountered exceptions.
        // If they're actually recoverable and you see them in crash reports, update this check.
        else -> true
    }
}
```

`FxaException.Forbidden` — the variant AS-2 maps every 403 to — has no typealias in this file
and is not on the list, so it takes `else -> true`.

The path to a crash is four frames and all of them are in this repository:

1. `AccountSettingsFragment.syncNow()` — the *Sync now* button — runs
   `viewLifecycleOwner.lifecycleScope.launch { … refreshDevices(); pollForCommands() }`.
   No `CoroutineExceptionHandler`.
2. `pollForCommands()` calls `handleFxaExceptions(logger, "polling for device commands", { null }) { … }`.
3. `handleFxaExceptions` asks `shouldPropagate()` first (FA-3) and rethrows.
4. The exception leaves the coroutine with nothing to catch it. The browser force-closes.

**Note step 2.** The caller passes `{ null }` as its `default` — an explicit statement that it
can handle a failure by returning nothing. FA-3 makes that unreachable.

**Why it matters.** The policy is "crash on anything new, and add it to the list when the crash
reports arrive". That is a defensible choice for a library that owns both ends. It is not
defensible for an error type derived from an **HTTP status code returned by a server**, because
the set of servers is not closed — every self-hosted FxA deployment, and every Mozilla
deployment that flips `deviceCommandsEnabled` or `pushbox.enabled` (FXA-2), can produce a 403
on a polled route. Firefox for Android currently force-closes on a server answering a
documented, deliberate 403 from its own reference implementation.

**The fix is one line**: a `FxaForbiddenException` typealias, on the recoverable branch.

**Confirmed empirically.** fxa-lite answered `GET /account/device/commands` with 403/errno 202
— an answer chosen precisely because it is upstream's own for a deployment with no pushbox —
and the household's phone force-closed on *Sync now*. Changing the answer stopped the crashes.

**fxa-lite** now answers the empty-queue document, which is what upstream's own
`PushboxDB.retrieve` computes for an empty table. DIVERGENCE `device-commands-always-empty`.

## FA-2 — a failed profile fetch renders a signed-in account as "Sign in"

**Tier** — Defect: user-visible wrong state, no error anywhere.

**Where** — `android-components/…/service/fxa/store/SyncStoreSupport.kt:98-111`.

**What happens.**

```kotlin
override fun onAuthenticated(account: OAuthAccount, authType: AuthType) {
    ...
    coroutineScope.launch {
        val syncAccount = account.getProfile()?.toAccount(account) ?: return@launch
        store.dispatch(SyncAction.UpdateAccount(syncAccount))
    }
}
```

If `getProfile()` returns null the observer returns before the dispatch, so the sync store's
account stays null — the same state `onLoggedOut` sets with `UpdateAccount(null)`. The menu has
no way to tell "signed in, profile unavailable" from "signed out", and renders the sign-in item.

**Why it matters.** The account manager is not confused; Sync runs the entire time. Only the UI
is wrong, and it is wrong in the most alarming available direction — it invites the user to sign
in to an account that is already signed in, and signing in again is a plausible route to
duplicate device registrations.

A profile is decoration. An account's existence is not. Treating a decoration failure as
non-existence is the bug, independent of AS-1 being the reason the fetch failed.

**fxa-lite** is why this was found: its profile document omitted `avatar` (AS-1), which is
fixed. The Kotlin behaviour is unchanged and would recur on any profile fetch failure.

## FA-3 — `handleFxaExceptions` consults the allow-list before the caller's handler

**Tier** — Defect (design). This is FA-1's root cause.

**Where** — `android-components/…/service/fxa/Utils.kt`.

**What happens.**

```kotlin
} catch (e: FxaException) {
    // We'd like to simply crash in case of certain errors (e.g. panics).
    if (e.shouldPropagate()) {
        throw e
    }
    when (e) {
        is FxaUnauthorizedException -> { ...; postHandleAuthErrorBlock(e) }
        else -> { ...; handleErrorBlock(e) }
    }
}
```

`shouldPropagate()` is checked before the `when`, so `handleErrorBlock` — and the `default`
parameter of the two-argument overload, which is what most callers pass — is never invoked for
an exception the central allow-list has not heard of.

**Why it matters.** The API's shape promises that a caller can decide how to handle a failure;
`pollForCommands` passing `{ null }` is exactly that promise being taken up. The implementation
overrides it with a global policy, so a caller that has thought carefully about a failure mode
cannot express it, and the only place to fix any such case is by editing a `when` in a different
module.

Panics genuinely should propagate past a caller's handler. Everything reachable from an HTTP
status code should not.

**A shape that would work**: propagate unconditionally only for `FxaPanicException`, and let
`handleErrorBlock` see everything else, keeping `shouldPropagate` as the default the
`default`-taking overload supplies rather than as an override.

---

# How four of these compound

The individually-small ones chain into the crash, and no single project owns the result:

1. **FXA-2** — a deployment sets `deviceCommandsEnabled = false`, or has no pushbox, so a
   route mobile polls answers 403.
2. **FXA-1** — that 403 carries `retry-after: 30`, which on desktop would disable the whole
   account client for 30 s.
3. **AS-2** — on mobile the Rust client maps the 403 to `Forbidden` and discards the errno 202
   that says "feature absent, not forbidden".
4. **FA-3 + FA-1** — `Forbidden` is not on the recoverable allow-list and the caller's own
   handler cannot see it, so it is rethrown into an unhandled coroutine and the browser closes.

Each link is defensible alone. Together, a server flipping a documented configuration flag
force-closes Firefox for Android, and the only diagnostic is an unexplained crash.

The general lesson, which fxa-lite paid for twice: **a claim that an answer is legible has to
name who is reading it.** errno 202 is in the client's error table — the *JavaScript* client's.
The client that polls those routes is a Rust crate that dispatches on the status code alone.

---

# Checked and withdrawn

One finding was in the draft and did not survive re-reading at the pin. It is recorded because
a bug list with nothing withdrawn from it has not been checked.

**`sync15::fetch_incoming` drops the collection GET's `X-Last-Modified`** — it binds it to
`_timestamp` and discards it, while the engine's high-water mark comes from `info/collections`.
That looked like a window in which a record written by another client between this client's
download and its own upload would be skipped for good, because `set_uploaded` fast-forwards
`LAST_SYNC_META_KEY` to the *upload's* timestamp
(`places/src/bookmark_sync/engine.rs:970`).

It is not, and the thing that closes it is the precondition. The upload carries
`X-If-Unmodified-Since: coll_state.last_modified`, the same `info/collections` value, so a
concurrent write since then makes the upload 412 and `set_uploaded` never runs. With nothing to
upload, `PostQueue.last_modified` is still its initial `xius`, so the mark is rewritten to the
value `apply()` already stored. Either way, nothing is skipped.

The adjacent `// XXX - this upload strategy is buggy due to batching` comment in
`client/sync.rs:81-86` is a real defect and is upstream-acknowledged in place: with enough
records the client commits two server batches, and if the second fails the engine is never told
about the first. Its consequence is a re-upload, not a lost download, and it is flagged where it
lives, so it is not written up here.

# Deliberately not written up

Cosmetics and inconsistencies, one line each, so that the tier decision is visible rather than
implied:

- `DEFAULT_ERRROR` — three Rs — in the fxa errno table, `errors.py:20` in fxa-lite records the
  typo because the value is on the wire.
- `hash_device_id`'s parameter is named `fxa_uid` and is passed the already-hashed uid
  (syncstorage-rs). Reproduced as-is; nothing computes the wrong value.
- `get_bso_ids` and `get_bsos` return differently-shaped offset tokens — a bare row count and a
  timestamp bound. Reproduced, because a client paging either way relies on getting its own
  shape back.
- `/info/collections` is answered on an expired credential (syncstorage-rs). Reproduced.
- `Sorting::None` is legal on the wire under `#[serde(rename_all = "lowercase")]` and then falls
  through both query builders, so `sort=none` and an absent `sort` are the same request. fxa-lite
  used to reject the string and now normalises it; that was fxa-lite's divergence, not a defect.

# Reproducing any of this

```sh
git -C resources/fxa                  show <pin>:<path>
git -C resources/syncstorage-rs       show <pin>:<path>
git -C resources/application-services show <pin>:<path>
git -C resources/firefox-android      show <pin>:<path>
git -C resources/firefox              show <pin>:<path>
```

The pins are in `UPSTREAM.toml`; `mozilla/fxa` and `syncstorage-rs` are `[[repo]]` entries with
their path lists, and the other three are `[[reference]]` entries, pinned so exactly this kind
of claim can name a commit. Several checkouts are sparse or blobless, so `git show` against the
pinned tree is more reliable than reading the working directory — which is also what makes the
pin, rather than the checkout, the thing being cited.
