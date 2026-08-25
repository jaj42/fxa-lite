# Phase 10 — security audit: findings and triage

Baseline for the reading pass: 755 tests, `ruff check` / `ty check` clean, at `a9001dd`.

**All eight findings below are fixed.** Each one landed with tests, in `tests/test_security.py`,
numbered as they are numbered here; the "confirm and pin" items are pinned there too. The
accepted items are written up in the README's **Security** section rather than left here, because
an operator reads that file and does not read this one. 813 tests pass.

## Fixed

**F1 — Unbounded request bodies, before authentication.**
`syncstorage/__init__.py:93` does `await request.body()` before the HAWK signature is checked
(it must: the signature may cover the body), and `models.check_content_length` runs later still,
in the handler. Every pydantic route buffers its body the same way. `uvicorn` imposes no limit,
so an unauthenticated `POST /storage/1.5/1/storage/history` — or `/v1/account/login` — of 2 GB is
a memory event. Fix: a pure-ASGI body cap installed under `tracing.Trace`, 64 KiB by default and
`syncstorage.models.LIMITS.max_request_bytes` (2 625 536) below `/storage`, answering in the
envelope the path's tier speaks.

*Fixed:* `middleware.BodyLimit`, added under `tracing.Trace`. A declared `Content-Length` over the
limit is refused without reading a byte; a chunked body is counted as it arrives and refused the
moment it passes. 64 KiB by default, `LIMITS.max_request_bytes` below `/storage`, and the refusal
is rendered in the envelope the path's tier speaks — a middleware runs outside every exception
handler in `app.py`.

**F2 — `POST /v1/account/create` is open to the internet.**
No signup funnel was the decision; the wire-compatible route was kept anyway and nothing gates it.
On a public origin anyone can provision an account, and each attempt is one unauthenticated
scrypt (64 MiB, ~100 ms) with an attacker-chosen email. The content server never calls it —
`grep` over `content/assets/*.js` finds no reference — so gating it costs no real client. Fix:
`[security] open_registration`, default `false`, refusing with 403 / errno 202 and **no**
`retryAfter` (the phase-8 finding about `HawkClient._constructError` applies).

*Fixed:* `[security] open_registration`, default `false`, 403 / errno 202 with no `retryAfter`.
The test suite's own fixture turns it on, because the conformance client signs up over HTTP; the
default is tested against a config with no `[security]` table at all.

**F3 — No throttle in front of the scrypt call.**
The plan's open question. Decision: throttle
**failed** password checks per normalized email, before scrypt, answering 429 / errno 114 with
`retryAfter` and a `Retry-After` header (upstream's `AppError.tooManyRequests`,
`app-error.ts:523`). Counting failures only means a user who knows their password can never be
locked out by an attacker who does not. `accounts.authenticate` raises `unknown_account` *before*
stretching, so an unknown email costs one indexed SELECT and cannot drive scrypt at all; with F2
that leaves `/account/login` as the only unauthenticated path to it (`/session/reauth` and
`/account/destroy` are session-authed). The table is capped so unknown emails cannot grow it.
Per-IP limiting stays the proxy's job — behind nginx every client is `127.0.0.1` — and phase 11's
`limit_req_zone` ships uncommented.

*Fixed:* `throttle.FailureThrottle`, consulted by `accounts.authenticate` between the account
lookup and `onepw.stretch` — so an unknown address still never reaches scrypt and still never
earns an entry. Ten failures per account in five minutes, then 429 / errno 114 with both
`retryAfter` and `Retry- After`; a correct password clears the tally. Configurable under
`[security]`.

**F4 — `tracing.SECRET_KEYS` misses the tokenserver's own response.**
`/token/1.0/sync/1.5` answers `{"id": …, "key": …}`: `id` is the HAWK credential and `key` is the
derived MAC key. Neither is in `SECRET_KEYS`, so `[log] level = "debug"` writes a complete,
spendable Sync credential to the log. `key` can go in globally (nothing else emits that JSON key);
`id` cannot (BSO ids, device ids, client ids), so it needs to be path-scoped. Also missing:
`pushAuthKey` / `pushPublicKey`, and `keyRotationSecret` for hygiene.

*Fixed:* `key`, `keyRotationSecret`, `pushAuthKey` and `pushPublicKey` added globally; `id` added
through a new `PATH_SECRET_KEYS`, scoped to `/token/` so a BSO id stays readable everywhere else.

**F5 — The SQLite file is created world-readable.**
`sqlite3.connect` uses the umask, so
`fxa.sqlite` lands 0644. It holds `kA` in the clear, the sealed key bundles, and — because the
accounts API authenticates on the token *id* and verifies no MAC — the session token ids are
themselves the credential clients present. Fix: chmod 0600 immediately after connect and before
`PRAGMA journal_mode = WAL`, which is what makes SQLite create `-wal`/`-shm` with the same mode.
`keygen` already writes the signing key 0600 through `os.open(..., 0o600)`; `serve` never widens
it (`oauth/keys.py` only reads) — add a warning when it is found group- or world-readable.

*Fixed:* `db._restrict` chmods it 0600 immediately after `connect` and before `PRAGMA journal_mode
= WAL`, which is what makes SQLite create `-wal`/`-shm` with the same mode; an existing wider file
is narrowed. The signing key is warned about rather than narrowed — it may be a mount or an
injected secret — and `keygen` still writes it 0600.

**F6 — Security headers stop at the shell.**
`content/__init__.py` puts CSP, `Referrer-Policy`,
`X-Frame-Options` and `nosniff` on the HTML document only. `/static/icon.svg` is served as
`image/svg+xml` from the same origin with none of them, and no API response carries `nosniff`.
Fix: the headers on the asset route too, and `nosniff` plus a `default-src 'none'` CSP on every
response that has not already set one.

*Fixed:* `middleware.SecurityHeaders` adds `nosniff` and `default-src 'none'; frame-ancestors
'none'` to every response that has not set its own, error envelopes included; the asset route now
carries the shell's full set.

**F7 — The profile server reflects parser detail.**
`profile/__init__.py:69` passes
`str(jose.JWTError)` into the response `reason`, and those messages interpolate attacker input
(`jose.py:245` `alg`, `:250` `kid`). JSON-escaped and length-capped at `MAX_JWT_LENGTH`, so not
exploitable — but it is unnecessary reflection on an unauthenticated route. Fix: a constant reason.

*Fixed:* A constant `"Invalid token"`.

**F8 — `ruff`'s `S` ruleset has never run.**
10 findings in `src`: 6 × S105 false positives
(`"passwordChangeToken"`, `"at+JWT"`, `"refresh_token"` …) and 4 × S608 over `store.py`, all of
which are legitimate (see below). Add `S` to `select` with `assert` scoped off in `tests/`.

*Fixed:* `S` is in `select`; `tests/**` ignores the six rules a test suite legitimately trips, and
the ten findings in `src` carry a `noqa` with the reason.

## Confirmed and pinned (no code change needed)

Each of these is now a test in `tests/test_security.py`.

- **HAWK grants no more than Bearer.** `_bearer_id` is strict per token kind; `_hawk_id` accepts
  any 64-hex id. It cannot escalate — `session_token()` and `key_fetch_token()` are separate
  tables and the two ids are HKDF'd under different `tokenTypeID`s — but nothing says so today.
- **A dropped scope cannot be regranted on refresh.** `strictScopeValidation` drops at
  authorization; `_refresh_token_grant` bounds widening by `scope ∪ allowed_scopes ∪
  TRUSTED_ALLOWED_SCOPES`, so the dropped scope errors rather than appearing.
- **`grant.py:254` is the only minter of the tokenserver audience**, which is what the
  tokenserver's stricter-than-upstream `aud` check rests on.
- **The HAWK payload hash cannot be stripped.** `hash` is a field *inside* the normalized string
  (`hawk.py:96`), so removing it from the header changes the MAC input. What an omitted hash costs
  is an unauthenticated *body* on a request the client never hashed — the specification's own
  answer, and moot under the TLS phase 8 made mandatory. There is no nonce cache, so a captured
  request is replayable within the (upstream's own, one-year) skew; same as upstream.
- **The derived tokenserver secret is domain-separated.** `SECRET_INFO`
  (`b"fxa-lite/tokenserver-shared-secret"`) is HKDF'd over the PKCS#8 DER of the signing key and
  appears nowhere else; the key's only other use is RS256.
- **Every f-string SQL fragment is a literal.** `store.py:246/365/387/447/450/510` interpolate
  only `','.join('?' * n)`, a fixed column list, and `orders`/`conflict` values chosen from
  literals. `query.sort` reaches SQL only through `orders.get(...)`.
- **`hmac.compare_digest` everywhere it matters** — password verify (`onepw.py:149`), code and
  client-id comparison, the HAWK MAC and payload hash, the tokenlib signature.
- **No route reads `Host`.** Every URL comes from `public_url`; `request.url` is read only for the
  HAWK resource string, which is correct.
- **Device routes are all scoped by `credentials.account.uid`.**
- **No envelope leaks a traceback, a SQL fragment or a path**; `errors.unexpected_error()` is a
  fixed message and the bare-`Exception` handler is registered.

## Accepted, with the reasoning written into the docs

All five are in the README's **Security** section, under *Accepted, with the reasoning*.

- A database leak yields live session credentials, because the stored token id *is* what a client
  presents — upstream's design, and the reason codes and refresh tokens are stored under `sha256`
  while these are not. `kB` still needs the password.
- `POST /v1/account/status` and errno 102 are an account-existence oracle, as upstream; and
  because an unknown email skips scrypt, a timing oracle too. F3's failure counter does not close
  it and is not meant to.
- No quota: `max_total_bytes` is advertised but not enforced and `/info/quota` reports null, so an
  authenticated account can fill the disk.
- No password reset means a forgotten password is unrecoverable *and* that there is no reset flow
  to attack. No 2FA means the password is the whole authenticator for `kB`; the CLI's 12-character
  minimum is the only control and nothing rotates the key.
- A failed PKCE verification does not burn the code (it is deleted only after the check passes),
  so the verifier may be retried until the code expires. Guessing a 43-character verifier's SHA-256
  preimage in 15 minutes is not a threat.

## Noted, not fixed

- **HAWK signs the decoded path.** `request.url.path` is `scope["path"]`, percent-decoded, where
  syncstorage-rs signs the raw target. `BSO_ID_RE` admits `%`, ` ` and `#`, so an id containing one
  would fail verification. No shipping client uses such an id (Sync ids are GUIDs and base64url),
  and MAC and routing read the same decoded string, so there is no escalation — an interop edge,
  not a security one.

## Addendum — the refresh-token auth scheme, audited after the fact

The audit above ran at `a9001dd`, before a phone had ever been pointed at fxa-lite. Phase 8's
mobile half then added a third auth scheme, two routes and a schema migration (`48a2654`), which
is precisely the sequence the plan warned about. This is that diff re-read against the categories
above; it is a diff review, not a second pass over the tree.

**Nothing new to fix.** What was checked, and why each one is the question worth asking:

- **The new scheme cannot escalate into an old one, in either direction.** `Bearer <64 hex>` with
  no prefix resolves only through `refresh_credentials`; `_bearer_id` still demands the `fx*_`
  prefix per token kind, so a refresh token cannot reach a session-token route. The reverse needs
  a SHA-256 preimage: refresh tokens are looked up under `hash_token`, so presenting a session
  token id as one finds nothing. `DeviceAuth` is on four routes and nothing else.
- **The uid-scoping property holds.** The refresh path resolves the account from the token's own
  `uid` and every device route still keys on `credentials.account.uid`; the new
  `device_by_refresh_token` is reached only after that resolution, and `delete_device` looks the
  row up by `(uid, id)` before deleting anything alongside it.
- **The database-leak note is unchanged, and slightly better than it was.** A refresh token is
  stored under `sha256`, so a leaked `refresh_tokens` row is not a spendable credential — unlike a
  session token id, which is. A phone's connection is therefore *not* in the category the README's
  Security section warns about.
- **`POST /v1/destroy` is unauthenticated on purpose** ("for legacy reasons it is possible to call
  this endpoint without credentials" — upstream's own comment). What it grants an observer is
  revocation, not access, and only for a token they already hold or whose id they have learned;
  `refresh_token_id` is deliberately not in `SECRET_KEYS` for the same reason. The `client_id`
  check is `hmac.compare_digest`, as its sibling's is.
- **The schema-v4 unique index cannot be tripped into a 500.** A refresh token that owns a record
  and then names a different one is refused with errno 124 *before* the upsert, so one token can
  never reach two rows. That was an assertion about control flow until
  `test_a_phone_cannot_claim_another_devices_row` made it a test.
- **`SECRET_KEYS` was extended by inspection rather than by accident** — see the phase 8 notes in
  `plan.md`. Three of `/v1/destroy`'s four field names were already redacted; the fourth is argued
  for rather than overlooked.
- No new f-string SQL, no new comparison of a secret with `==`, no new read of `Host`, and no new
  error envelope: the four mechanical properties the `S` rules and the pinned tests cover.
