# Architecture

Six tiers that upstream deploys separately, served from one origin by one
FastAPI application, backed by one SQLite file.

```{mermaid}
flowchart LR
    FF["Firefox<br/>desktop / Android"]
    subgraph P["one process, one origin"]
        C["content server<br/>/"]
        A["accounts API<br/>/v1"]
        O["OAuth<br/>/v1"]
        PR["profile<br/>/profile/v1"]
        T["Sync tokenserver<br/>/token"]
        S["Sync storage<br/>/storage"]
    end
    DB[("fxa.sqlite<br/>WAL")]
    FF --> C
    FF --> A
    FF --> O
    FF --> PR
    FF --> T
    FF --> S
    C --> A
    A --- DB
    O --- DB
    PR --- DB
    T --- DB
    S --- DB
```

## Why one process

Not thrift, though it is that too. The reference stack splits accounts and
tokens across MySQL, sessions and devices across eight Redis hostnames, and
profile data into Firestore, because at Mozilla's scale those tiers have
genuinely different load, different failure domains and different teams. A
household has one of each.

What the merge buys, beyond the operational saving, is that three things stop
being distributed problems:

* **The tokenserver's user table can hold a real foreign key.** Upstream keys
  Sync users on the string `<fxa_uid>@<email domain>` because its tokenserver
  has never seen the accounts table. Here it is the same file, so deleting an
  account takes its Sync storage with it
  ({ref}`marker <divergence-sync-users-real-foreign-key>`).
* **The tokenserver and the storage tier need no shared secret to be
  configured**, because there is nobody to agree with
  ({ref}`marker <divergence-tokenserver-secret-derived>`).
* **The tokenserver verifies access tokens against a key in memory** rather
  than fetching and caching `/v1/jwks` over HTTP.

What it costs is that the tiers can no longer be scaled or restarted
independently, and that a schema migration touches all of them at once. For a
handful of accounts that is not a compromise, it is the point.

## The prefix layout

`/.well-known/fxa-client-configuration` tells Firefox where each piece lives, so
with one exception the layout is entirely fxa-lite's choice.

| Prefix | Role | Reference package |
|---|---|---|
| `/v1/…` | accounts API **and** OAuth server | `fxa-auth-server` (one process upstream too) |
| `/profile/v1/…` | profile server | `fxa-profile-server` |
| `/`, `/signin`, `/oauth/signin`, `/authorization`, `/settings`, `/pair` | content server (the WebChannel page) | `fxa-content-server` + `fxa-settings` |
| `/token/1.0/sync/1.5` | Sync tokenserver | `syncstorage-rs/syncserver/src/tokenserver` |
| `/storage/1.5/{uid}/…` | Sync storage | `syncstorage-rs/syncstorage-*` |
| `/.well-known/fxa-client-configuration`, `/.well-known/openid-configuration` | discovery | `fxa-content-server` |
| `/__version__`, `/__heartbeat__`, `/__lbheartbeat__` | operational | `lib/routes/defaults.js` |

The exception is `/`. `identity.fxaccounts.autoconfig.uri` points a browser at
an origin, and what opens there has to be the sign-in page — so the auth
server's version document, which upstream also serves at `/`, lives only at
`/__version__` ({ref}`marker <divergence-root-belongs-to-the-content-server>`).

## The three middlewares

Added innermost-first, so a request meets them outermost-first:

```{mermaid}
flowchart TB
    R["request"] --> TR["tracing.Trace"]
    TR --> SH["middleware.SecurityHeaders"]
    SH --> BL["middleware.BodyLimit"]
    BL --> RT["route"]
```

**`tracing.Trace`** costs one `isEnabledFor` call at the default log level. At
`debug` it renders every request and response with its body, redacting by key
name — `authPW`, session and key-fetch tokens, access and refresh tokens,
`keys_jwe`, Sync payloads — down to a prefix and a length. It is outermost so
that a request which never reaches a route is still described, and so the status
a handler actually produced is the one recorded.

**`middleware.SecurityHeaders`** stamps `nosniff` and
`default-src 'none'; frame-ancestors 'none'` on every response that has not set
its own, error envelopes included. The sign-in page and its assets set their own,
fuller, policy.

**`middleware.BodyLimit`** refuses an oversized body before anything reads it:
a declared `Content-Length` over the limit without reading a byte, a chunked body
the moment it passes. 64 KiB by default and `max_request_bytes` below
`/storage`. It has to be a middleware rather than a route dependency because
every tier reads the body *before* it checks the signature — it must, since the
signature may cover the body — so "authenticate first" was never available.

## Three error envelopes

This is the part a reader's first instinct calls sloppiness. It is not: the
three tiers were three deployments with three histories, Firefox has a separate
parser for each shape, and converging them would break the client.

**The accounts API, OAuth and profile** — `{code, errno, error, message, info}`:

```json
{"code": 400, "errno": 121, "error": "Bad Request", "message": "Invalid grant_type"}
```

Clients read `errno`, not the HTTP status. That is why an unhandled exception
escaping as FastAPI's `{"detail": …}` is not "a 500 with a different body" but a
response the client cannot interpret at all — and why `app.py` registers a
handler for bare `Exception`. The profile server has its own errno table,
overlapping but not identical.

**The tokenserver** — `{status, errors: [{location, name, description}]}`:

```json
{"status": "invalid-client-state",
 "errors": [{"location": "header", "name": "X-Client-State",
             "description": "Unauthorized"}]}
```

It grew out of a Pyramid/cornice service and never converged with the Node
stack. `status` is the field that carries meaning: `invalid-client-state` tells
Firefox its Sync key no longer matches what the server has seen and it should
re-authenticate, where a generic 401 leaves it retrying a dead token forever.

**Sync storage** — a bare JSON integer, the Weave error code, as the whole body:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

8
```

Sync 1.5 inherited the format from Sync 1.1, and `error.rs` keeps the
descriptive body commented out for backwards compatibility. Only six values are
ever sent. The status matters more than the code: `8` says the record is
malformed and will never be accepted, a 503 with `Retry-After` says ask again
shortly, and that is what decides whether the client drops the record, retries,
or gives up on the collection.

`app.py` therefore routes 404s and 405s by prefix as well: a 404 below
`/storage/` is an integer and a 404 below `/token/` is a tokenserver envelope,
because handing either tier the accounts shape looks to its parser like a
success with no fields.

## The schema

One SQLite file in WAL mode, `sqlite3` from the stdlib, connections per thread.
Two conventions carried from upstream because they leak onto the wire:
timestamps are **integer milliseconds**, and every key, token id and uid is a
**lowercase hex string** rather than a blob — that is the form the API speaks,
and hex round-trips without adapters.

Four migrations, stamped in SQLite's `user_version`. A database from a future
version refuses to open rather than guessing.

```{mermaid}
erDiagram
    accounts ||--o{ session_tokens : "signs in"
    accounts ||--o{ key_fetch_tokens : "single use"
    accounts ||--o{ devices : "registers"
    accounts ||--o{ oauth_codes : "grants"
    accounts ||--o{ refresh_tokens : "grants"
    accounts ||--o{ sync_users : "one per client state"
    session_tokens ||--o| devices : "owns (desktop)"
    refresh_tokens ||--o| devices : "owns (mobile)"
    sync_users ||--o{ sync_user_collections : ""
    sync_users ||--o{ sync_bso : ""
    sync_users ||--o{ sync_batches : ""
    sync_batches ||--o{ sync_batch_items : ""
    sync_collections ||--o{ sync_bso : "names"
```

### What each table is, and how long it lives

`accounts` (v1)
: One row per person, forever. Holds `kA` in the clear, `wrapWrapKb` (useless
  without the password), the scrypt salt and verify hash, and `keys_changed_at`
  — which is half of every Sync `kid`. Never holds `kB`.

`session_tokens` (v1)
: One per signed-in browser, until it signs out or the account is removed. The
  stored `token_id` **is** the credential a client presents, which is why a copy
  of this database is a set of live sessions. `auth_key` is the HAWK MAC key,
  stored because the protocol says so and verified by nobody
  ({ref}`why <divergence-hawk-macs-unverified>`).

`key_fetch_tokens` (v1)
: Minutes. Created at sign-in when `?keys=true`, holds `kA || wrapKb` already
  bundled under the token's `bundleKey`, and the row is deleted the moment it is
  read. Single use is the whole design.

`devices` (v1, index in v4)
: One per browser that registered itself. Owned by a session token (desktop) or
  by an OAuth refresh token (mobile) — two partial unique indexes, because a
  device that cannot be found by the credential presenting it becomes a new
  orphan on every reconnect.

`oauth_codes` (v1)
: Fifteen minutes, or until exchanged. Carries the PKCE challenge and the
  `keys_jwe` blob, which the server stores and echoes back without ever being
  able to decrypt it. Stored under SHA-256.

`refresh_tokens` (v1)
: Until revoked. Stored under SHA-256, so a leaked row is not a spendable
  credential — unlike a session token id.

`sync_users` (v2)
: One row per *client state*, not per account. A key rotation does not update
  the row, it **replaces** it: the new key material gets a new small integer uid
  and cannot read records encrypted under the old one. The old row stays as the
  record of a client state that must never be accepted again.
  `AUTOINCREMENT`, because SQLite reuses the largest rowid after a delete and a
  recycled uid would hand a new user the previous one's collections.

`sync_collections`, `sync_user_collections`, `sync_bso` (v3)
: The storage itself, hanging off `sync_users.uid` rather than the FxA uid —
  which is the point of the split. Collection id 0 is a reserved tombstone that
  belongs to no collection, so that deleting a collection can move the storage
  timestamp without leaving a collection behind to carry one. Expiry is stored
  as an absolute instant and filtered on read; there is no sweeper.

`sync_batches`, `sync_batch_items` (v3)
: An upload in progress. Rows accumulate across several POSTs and land in
  `sync_bso` at one shared timestamp when the client commits. The batch id is a
  millisecond timestamp, which is also how its lifetime is checked.

## Authentication, by tier

Four schemes, and knowing which one a route uses explains most of its behaviour.

| Where | Header | Verified how |
|---|---|---|
| accounts API | `Hawk id="<tokenId>"` **or** `Bearer fxs_<tokenId>` | the id is looked up; the MAC is parsed and discarded |
| accounts API, device routes | `Bearer <64 hex>`, no prefix | an OAuth refresh token, looked up under SHA-256, and its grant is checked |
| OAuth, profile | `Bearer <JWT>` | RS256 against the in-process signing key |
| Sync storage | `Hawk id="<tokenlib token>"` | **fully verified**: MAC over the normalized string, payload hash when sent |

The first row is upstream's design and the second is upstream's `refresh-token`
scheme; the fourth is a different protocol that happens to share a word. HAWK
grants nothing that the equivalent Bearer does not: `Bearer fx*_` is strict per
token kind, session and key-fetch ids live in separate tables, and the two are
HKDF'd under different `tokenTypeID`s. `tests/test_security.py` pins that.
