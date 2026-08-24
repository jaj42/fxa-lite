# fxa-lite — a slim, self-hosted Mozilla Accounts + Sync stack in Python

## Context

Mozilla Accounts (FxA) is open source, but the reference monorepo at `resources/fxa` is built to
run a service for hundreds of millions of users. Standing it up self-hosted (see
`resources/fxa-selfhosting/docker-compose.tmpl.yml`) means MySQL, Redis (eight separate Redis
hostnames), Firestore, an SMTP relay, nginx, a channelserver, and a Node monorepo — plus
`syncstorage-rs`, which itself only supports MySQL/Postgres/Spanner.

We want the same thing for a handful of accounts (one household, not one planet): **one Python
executable, one SQLite file, no external services**, wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

Intended outcome: `uvx fxa-lite --config fxa.toml` starts everything — accounts API, OAuth/OIDC,
profile, the sign-in web page, the Sync tokenserver, and Sync storage — on a single origin.

### Decisions already made

- **Keep the real onepw protocol** (email + password, client-side PBKDF2/HKDF). It is the only
  thing Firefox knows how to do, and the password *is* the Sync encryption key. Multiple accounts
  are supported (it costs one `accounts` table); what we drop is the *management* around them —
  no signup funnels, no email verification, no password reset, no 2FA, no unblock codes.
  Accounts are provisioned by CLI.
- **Match the reference auth scheme exactly**: accept both `Hawk id="<tokenId>"` and
  `Bearer fx{s,k,ar,pf,pc}_<64hex>`, and do **not** verify HAWK MACs — today's Mozilla server
  doesn't either (`lib/routes/auth-schemes/hawk-fxa-token.js` parses the header and throws away
  `mac`/`ts`/`nonce`). Sync *storage* HAWK is a different protocol and **is** fully verified.
- **Own tokenserver + syncstorage in Python/SQLite**, rather than syncstorage-rs + Postgres.
- **Conformance testing via a Python port of `fxa-auth-client`**, plus known-answer vectors
  lifted from the reference `*.spec.ts` files.

---

## Architecture

One FastAPI app, one origin, sub-apps mounted by prefix. `/.well-known/fxa-client-configuration`
tells Firefox where each piece lives, so the prefix layout is entirely our choice.

| Prefix | Role | Reference package |
|---|---|---|
| `/v1/...` | auth server **and** OAuth server | `fxa-auth-server` (they are one process upstream) |
| `/profile/v1/...` | profile server | `fxa-profile-server` |
| `/` , `/signin`, `/pair`, `/authorization`, `/settings` | content server (WebChannel HTML) | `fxa-content-server` + `fxa-settings` |
| `/token/1.0/sync/1.5` | Sync tokenserver | `syncstorage-rs/syncserver/src/tokenserver` |
| `/storage/1.5/{uid}/...` | Sync storage | `syncstorage-rs/syncstorage-*` |

### Dependencies

`fastapi`, `uvicorn[standard]`, `cryptography`. That is the whole list.

`cryptography` is unavoidable: the stdlib has no RSA (needed for RS256 JWTs + `/v1/jwks`) and no
P-256 ECDH (needed for the `keys_jwe` scoped-key bundle). Everything else — PBKDF2, scrypt,
SHA-256, HMAC, AES-GCM (via `cryptography`'s AESGCM), CSPRNG, SQLite — is stdlib. **HKDF, JWT
sign/verify, and JWE compact ECDH-ES we implement ourselves** (~120 lines total); pulling in
`pyjwt` + `jwcrypto` to save that is not worth the dependency surface.

### Layout

```
pyproject.toml            # uv-managed; [project.scripts] fxa-lite = "fxa_lite.cli:main"
fxa.example.toml          # annotated config template; copy to fxa.toml (gitignored)
src/fxa_lite/
  cli.py                  # `serve`, `account add|list|remove`, `keygen`
  config.py               # TOML -> dataclass; public_url, listen, jwks paths, token TTLs
  app.py                  # FastAPI assembly + mounts
  errors.py               # FxA error envelope {code,errno,error,message,info} + errno table
  db.py                   # sqlite3 (stdlib), WAL, schema DDL, migrations
  crypto/
    hkdf.py               # RFC 5869 HKDF-SHA256
    onepw.py              # quickStretch v1/v2, verifyHash, wrapwrapKey, bundle/unbundle
    tokens.py             # Token.deriveTokenKeys -> (id, authKey, bundleKey)
    scoped_keys.py        # scoped-key derivation incl. the legacy oldsync path
    jose.py               # RS256 JWT sign/verify, JWK<->key, ECDH-ES+A256GCM compact JWE
  auth/                   # routes: account, session, recovery_email, devices
  oauth/                  # routes: authorization, token, verify, introspect, destroy,
                          #         jwks, key_data
  profile/
  content/                # Jinja-free static HTML + vanilla-JS WebChannel client
  tokenserver/
  syncstorage/
tests/
  vectors/                # KATs transcribed from the reference *.spec.ts files,
                          #   plus signing-key.pem, the fixed RSA key behind the kid KAT
  conformance/client.py   # Python port of fxa-auth-client (crypto.ts + hawk.ts + bearer.ts)
  test_*.py
```

---

## Protocol constants (verified against the reference — do not paraphrase these)

All KDF namespacing is `identity.mozilla.com/picl/v1/`. Every HKDF below is HKDF-SHA256 with an
**empty salt** (RFC 5869 default → 32 zero bytes) unless stated otherwise.

**Client-side credential derivation** — `packages/fxa-auth-client/lib/crypto.ts`, `lib/salt.ts`:
```
v1 salt = "identity.mozilla.com/picl/v1/quickStretch:" + email        , 1000 iterations
v2 salt = "identity.mozilla.com/picl/v1/quickStretchV2:" + <32-hex>   , 650000 iterations
quickStretchedPW = PBKDF2-HMAC-SHA256(password, salt, iters, dkLen=32)
authPW     = HKDF(quickStretchedPW, info="identity.mozilla.com/picl/v1/authPW",     L=32)
unwrapBKey = HKDF(quickStretchedPW, info="identity.mozilla.com/picl/v1/unwrapBkey", L=32)
```
Note the lowercase `k` in `unwrapBkey`.

**Server-side password storage** — `packages/fxa-auth-server/lib/crypto/password.js`:
```
authSalt  = 32 random bytes (hex)
stretched = scrypt(authPW_bytes, authSalt_bytes, N=65536, r=8, p=1, dkLen=32)  -> HEX STRING
verifyHash = HKDF(ikm=UTF8(stretched_hex), info=".../verifyHash",    L=32)
wrapper    = HKDF(ikm=UTF8(stretched_hex), info=".../wrapwrapKey",   L=32)
wrapWrapKb = wrapper XOR wrapKb      (stored)     wrapKb = kB XOR unwrapBKey
```
The IKM really is the *hex string's ASCII bytes*, not the 32 raw bytes — the Node `hkdf` package
does `Buffer.from(string)`. Reproduce literally or nothing interoperates.

**Token derivation** — `packages/fxa-auth-server/lib/tokens/token.js`:
```
keyMaterial = HKDF(tokenData_32B, info=".../" + tokenTypeID, L=96)
id = km[0:32]   authKey = km[32:64]   bundleKey = km[64:96]
tokenTypeID ∈ {sessionToken, keyFetchToken, accountResetToken,
               passwordChangeToken, passwordForgotToken}
```
`id` hex is the HAWK id / Bearer body. `authKey` is the (unverified) HAWK MAC key.

**`GET /v1/account/keys` bundle** — `lib/tokens/bundle.js`, `key_fetch_token.js`:
```
km        = HKDF(keyFetchToken.bundleKey, info=".../account/keys", L=32+64)
hmacKey=km[0:32]  xorKey=km[32:96]
ciphertext = (kA || wrapKb) XOR xorKey ; mac = HMAC-SHA256(hmacKey, ciphertext)
bundle = hex(ciphertext || mac)   # 192 hex chars, precomputed at token creation, single-use
```

**Scoped keys** — `libs/vendored/crypto-relier/src/lib/deriver/scoped-keys.ts`:
```
general: HKDF(salt=uid_bytes, ikm=kB||keyRotationSecret, L=48,
              info="identity.mozilla.com/picl/v1/scoped_key\n" + scope)
         kid = round(keyRotationTimestamp/1000) + "-" + b64url(km[0:16]) ; k = b64url(km[16:48])
oldsync: HKDF(salt=b"", ikm=kB, info="identity.mozilla.com/picl/v1/oldsync", L=64)
         k = b64url(km) ; kid = keyRotationTimestamp + "-" + b64url(sha256(kB)[0:16])
```
`keyRotationSecret` is always 64 zeros; `keyRotationTimestamp` is the account's `keysChangedAt`
in ms. The oldsync path also applies to `https://identity.thunderbird.net/apps/sync`.

**`keys_jwe`** — `deriver-utils.ts`: compact JWE, `alg=ECDH-ES`, `enc=A256GCM`, recipient key is
the client's P-256 **public** JWK, delivered base64url-encoded as the `keys_jwk` parameter.
Plaintext is `{"<scope>": <scopedKeyJWK>, ...}`. The auth server never decrypts it — it stores
the blob on the code row and echoes it back at token time.

**tokenlib** (tokenserver → syncstorage) — `syncstorage-rs/tokenserver-auth/src/token/native.rs`:
```
payload   = JSON{node, fxa_kid, fxa_uid, hashed_fxa_uid, hashed_device_id,
                 expires, uid, tokenserver_origin, salt}   # salt = 3 random bytes, hex
hmac_key  = HKDF(shared_secret, salt=None, info=b"services.mozilla.com/tokenlib/v1/signing")
token     = b64url(payload_bytes || HMAC-SHA256(hmac_key, payload_bytes))
derived   = b64url(HKDF(shared_secret, salt=salt_ascii,
                        info=b"services.mozilla.com/tokenlib/v1/derive/" + token))
```
Response: `{id: token, key: derived, uid, api_endpoint: "<node>/1.5/<uid>", duration,
hashed_fxa_uid, hashalg: "sha256", node_type}` + `X-Timestamp`, `X-Content-Type-Options: nosniff`.

**JWT access token** — `lib/oauth/jwt_access_token.js`: header `typ: "at+JWT"`, RS256,
`iss = openid.issuer`. Claims `aud, client_id, exp, iat, jti, scope, sub` (+`fxa-generation`,
`fxa-profileChangedAt`, `acr`, `auth_time`). **When scope contains
`https://identity.mozilla.com/apps/oldsync`, `aud` is the tokenserver URL, not the client_id.**
`scope` is space-separated. TTL ≤ 6 h means the token never needs a server-side store.

**Firefox Desktop client** — id `5882386c6d801776`, public + trusted + canGrant, redirect
`urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel`, allowed scopes
`https://identity.mozilla.com/apps/oldsync https://identity.mozilla.com/tokens/session
https://identity.mozilla.com/ids/ecosystem_telemetry`. PKCE S256 mandatory (public client).
Seed this client plus Fenix `a2270f727f45f648` and iOS `1b1a3e44c54fbb58` from config.

---

## Phases

Each phase ends green before the next starts.

### Phase 0 — scaffolding ✅ done
`uv init --package --python 3.12`, then `uv add fastapi "uvicorn[standard]" cryptography` and
`uv add --dev pytest pytest-asyncio httpx ruff ty`. Config dataclass reading TOML
(`tomllib`, stdlib). `fxa-lite keygen` writes the RSA-2048 signing JWK, using the reference kid
convention `YYYYMMDD-<sha256(pubkey_pem)[:8]>`.

As built:

- `config.py` — frozen dataclasses, unknown keys rejected (a typo must fail, not silently
  default). `public_url` validated as an absolute http(s) URL and stored without its trailing
  slash; paths relative to the config file resolve against its directory, so config + SQLite +
  signing key move as a unit. Sections: `[listen]` host/port, `[paths]` database/signing_key/
  retired_key, `[ttl]` access_token (21600 — at or below fxa-shared's
  `SHORT_ACCESS_TTL_TOKEN_IN_MS`, which is what keeps access tokens out of a server-side store),
  authorization_code (900, `oauthServer.expiration.code`), tokenserver_token (3600,
  syncstorage-rs `token_duration`), plus `tokenserver_shared_secret`. Example in
  `fxa.example.toml`.
- `crypto/jose.py` — so far only the JWK half (base64url, minimal big-endian JWK integers,
  RSA-2048 keygen, `key_id`, private/public JWK conversion). JWT and JWE follow in phase 1.
- `cli.py` — `keygen [-c fxa.toml] [-o PATH] [--force]`; writes the private JWK 0600 through a
  temp-file rename and refuses to clobber an existing key.
- The kid convention is the **OAuth** one, `lib/oauth/keys.ts:generatePrivateKey`: sha256 over the
  **PKCS#1** public PEM (`-----BEGIN RSA PUBLIC KEY-----`, trailing newline included), and the JWK
  also carries `alg: RS256`, `use: sig`, `fxa-createdAt` floored to the hour. `scripts/gen_keys.js`
  has a different, older convention (`YYYY-MM-DD-<sha256(n||e)[:32]>`) for the retired BrowserID
  key — not ours.
- Verified: `tests/test_jose.py` pins the kid against `tests/vectors/signing-key.pem`, with the
  expected fingerprint and the modulus produced by `openssl`, not by our own encoder.

### Phase 1 — crypto core, test-first ✅ done
Implement `crypto/` and validate against KATs transcribed from:
`packages/fxa-auth-server/lib/crypto/{hkdf,pbkdf2,scrypt,password,butil}.spec.ts`,
`lib/tokens/{token,key_fetch_token,session_token,account_reset_token}.spec.ts`,
`packages/fxa-auth-client/test/{crypto,salt,hawk,bearer}.ts`,
`libs/vendored/crypto-relier/src/lib/deriver/{scoped-keys,driver-utils}.spec.ts`.
Round-trip the JWE against `jweDecrypt` semantics in `fxa-auth-client/lib/crypto.ts`.
**This is the phase that decides whether the whole project interoperates.** Do not proceed on
"looks right" — proceed on byte-equal vectors.

As built:

- `crypto/hkdf.py` — RFC 5869 HKDF-SHA256, plus `kw`/`kwe`. An empty salt is 32 zero bytes,
  which is both what RFC 5869 specifies and what the Node `hkdf` package does with the `null`
  the reference server passes; every FxA derivation rests on that. `derive()` is the namespaced
  form the protocol actually speaks.
- `crypto/onepw.py` — salts (create/parse, v1 and v2), `quickStretch`, the client credential
  pair, and the server-side scrypt. `StretchedPassword.stretched` is deliberately a *hex string*:
  `password.js` feeds scrypt's hex output to `Buffer.from()`, so the HKDF input keying material
  is 64 ASCII bytes, not the 32 they spell. There is no upstream KAT for `verifyHash` or
  `wrapwrapKey` (`password.spec.ts` only round-trips), so that trap is pinned by a test asserting
  the hex-string derivation differs from the raw-bytes one.
- `crypto/tokens.py` — `TokenType`, the id/authKey/bundleKey derivation, the Bearer prefix table,
  and bundle/unbundle. Bundling lives here rather than in `onepw.py` as the layout above sketched,
  matching the reference (`lib/tokens/bundle.js`): the key it uses comes from a token, not a
  password.
- `crypto/scoped_keys.py` — general and legacy-Sync derivation. `Math.round(ts/1000)` is done as
  `(ts + 500) // 1000` so no float is involved. `client_state()` is the tokenserver's half of the
  Sync `kid`, needed in phase 5.
- `crypto/jose.py` — grew RS256 JWT sign/verify (one algorithm only; `alg: none` is rejected by
  construction) and compact JWE in both flavours. No reference vector exists for the ECDH-ES
  bundle, so the two halves are pinned separately against the specs node-jose implements:
  the concat KDF against RFC 7518 appendix C, and the AEAD framing — AAD is the ASCII base64url
  protected header, 12-byte IV, 16-byte tag in its own segment — against RFC 7516 appendix A.1.
- Vectors live in `tests/vectors/*.json`, each naming the spec file or RFC it came from; nothing
  there is generated by fxa-lite. 139 tests, `ruff check` and `ty check` clean.

### Phase 2 — accounts API ✅ done
SQLite schema (`accounts`, `sessionTokens`, `keyFetchTokens`, `devices`, `oauthCodes`,
`refreshTokens`, plus the sync tables later). Auth dependency accepting both header schemes.
Routes: `POST /v1/account/{create,login,status,destroy}`, `GET /v1/account/{status,keys,profile}`,
`GET /v1/recovery_email/status`, `POST /v1/session/{destroy,duplicate,reauth}`,
`GET /v1/session/status`, `POST /v1/account/device`, `GET /v1/account/devices`,
`POST /v1/account/device/destroy`, `POST /v1/get_random_bytes`, `GET /v1/account/credentials/status`,
`GET /config`, `/__heartbeat__`, `/__version__`.

Accounts created by CLI are `emailVerified: true` and sessions are pre-verified, so
`/v1/recovery_email/status` returns `verified: true` immediately — **Firefox stalls forever if it
doesn't**, and there is no mailer to unstall it.

As built:

- `errors.py` — the `{code, errno, error, message, info}` envelope plus factories for the errnos
  fxa-lite can actually raise (the full table is 230-odd values, nearly all about subscriptions,
  2FA and email). Rendered by four handlers in `app.py`, including one for bare `Exception`, so
  no route can answer with FastAPI's `{"detail": …}`: clients branch on `errno`, and a body
  without one is uninterpretable. Validation failures map to 108 (`missing`) or 107 (anything
  else), reporting the offending field name.
- `db.py` — schema, migrations (`user_version`, and a refusal to open a database from a *newer*
  fxa-lite), and every statement. Timestamps are integer milliseconds and keys/ids are lowercase
  hex strings, both because that is what the wire uses. Tables are `STRICT`. Connections are
  per-thread since FastAPI runs sync routes in a worker pool; `:memory:` is special-cased onto a
  shared-cache URI with a keeper connection, or each test thread would get its own empty database.
- `accounts.py` — new file, not in the layout above: provisioning, password checks and token
  minting, shared verbatim by the CLI and the API. `provision` returns the stretched password
  alongside the account so `create?keys=true` pays for scrypt once rather than twice, and
  `start_session` returns the stored row so `authAt` is *that token's*, not a second `now()` a
  millisecond later — the two disagreed across a second boundary, and a test caught it.
- `auth/credentials.py` — both header schemes, one lookup, no MAC verification, matching
  `hawk-fxa-token.js`. Bearer parsing is strict per token kind (`fxs_`/`fxk_`), so a plain
  `Bearer <hex>` refresh token and a session token can share a route without colliding. Every
  failure — missing, malformed, oversized, unknown, wrong kind — answers 401/errno 110, which is
  the reference's own choice: they are all the same instruction to the client.
- `auth/models.py` — the joi schemas as pydantic, `extra="forbid"` (joi strips unknown keys; a
  silently ignored typo is a week-long bug report). `validators.isValidEmailAddress` is
  transcribed rather than delegated to `EmailStr`, which would have added `email-validator` to a
  three-dependency project and disagrees at the edges — an address the reference accepts but we
  reject is an account that can never sign in.
- Two deliberate divergences, both documented at the routes: `metricsEnabled` is always `false`
  (there is no metrics pipeline to enable), and `/account/credentials/status` answers
  `upgradeNeeded: false` (upstream says `true` for any account without a v2 verifier, which asks
  the client to run a password change against a server that speaks v2 — we do not, so promising
  the upgrade would strand it mid-flow).
- `cli.py` grew `serve` and `account add|list|remove`. `add` requires 12 characters, not the
  reference's 8: the password is the Sync encryption key and nothing rotates it.
- Verified: 213 tests. The HTTP tier is driven through `httpx.ASGITransport` by
  `tests/conformance/client.py`, which re-derives HKDF, PBKDF2, the token triple and the key
  bundle from the protocol description rather than importing `fxa_lite.crypto` — one test asserts
  the two implementations agree, so a shared bug cannot hide. Every authenticated test runs twice,
  once per Authorization scheme. `ruff check` and `ty check` clean.

### Phase 3 — OAuth, profile, discovery ✅ done
`GET /v1/jwks`, `POST /v1/oauth/authorization` (sessionToken-authed, PKCE S256, `keys_jwe`
passthrough, service→scope resolution for `service=sync`), `POST /v1/oauth/token`
(`authorization_code` + `refresh_token`, single-use codes, 15-min expiry),
`POST /v1/account/scoped-key-data`, `POST /v1/verify`, `POST /v1/introspect`,
`POST /v1/oauth/destroy`, `GET /v1/client/{id}`, `GET /profile/v1/{profile,email,uid,display_name}`,
`/.well-known/{openid-configuration,fxa-client-configuration}`.

Collapse the internal `assertion` round-trip (`makeAssertionJWT` → `verifyAssertion`, HS256,
60 s TTL) into a direct call — it exists upstream only because auth and oauth used to be separate
services. Skip PPID, token-exchange, consent ledger, DAU metrics, subscriptions.

As built:

- `oauth/scopes.py` — `ScopeSet`, a port of `fxa-shared/oauth/scopes.ts`. Every access decision
  in this phase is `contains()`, and the implication rules are subtle enough (`profilebogey` does
  not imply `profile`; `profile:email:write` does not imply `profile:write`) that the upstream
  precomputed-implicants design is reproduced rather than reinvented as prefix matching.
  Iteration order is part of the contract — `getScopeValues` is `Object.keys` upstream, so a dict
  and an ordered implicant tuple keep JS and Python agreeing. URL scopes are stricter than
  `urlsplit` alone: upstream demands `new URL(value).href === value`, so `..` segments, uppercase
  hosts, a `:443` port and the characters the WHATWG parser percent-encodes are all rejected here
  by hand. The full spec tables live in `tests/vectors/scopes.json`.
- `oauth/clients.py` — the client registry. Upstream it is a MySQL table behind an admin panel;
  here the three browsers are built in with the ids, scopes and redirects `config/dev.json` gives
  them, and `[[clients]]` in the config adds or **replaces** one. Replacement is wholesale on
  purpose: a half-overridden client — new redirect, inherited scopes — is how a scope gets granted
  by accident. Every client is public, so PKCE is mandatory and there is no `client_secret`
  anywhere in the codebase.
- `oauth/grant.py` — `SessionClaims` is the assertion payload, passed as an object. One deliberate
  divergence: upstream's `strictScopeValidation` is off by default, so a trusted client asking for
  an unregistered scope is granted it; fxa-lite turns it on and *drops* the scope instead. A
  key-bearing scope outside the client's own allow-list is still a hard error (errno 114) — that
  is the check standing between a relier and `kB`. The access token is a JWT with `typ: at+JWT`
  and no server-side row; `jti` is therefore just a unique id rather than a table key.
- `oauth/keys.py` — the signing key is read at `create_app` time, not lazily: a missing key should
  stop the process, not surface as a 500 on the first sign-in. `paths.retired_key` publishes a
  second public JWK so a rotation does not invalidate tokens signed a minute earlier.
- `oauth/routes.py` — both route flavours. Authorization codes and refresh tokens are stored under
  `sha256` of themselves, as upstream stores them, so a database leak yields nothing redeemable.
  Abandoned codes are swept on the next authorization; there is no scheduler and the table is tiny.
  `_redirect_with_code` works on the `urn:…:oauth-redirect-webchannel` sentinel, which is not a
  location at all — the browser reads `code` and `state` off it instead of navigating.
- Errors: the OAuth routes answer from `OauthErrno`, a *different* numbering from the accounts
  API's — `108` is "invalid token" there and "missing parameter" here. That is upstream's own
  arrangement, kept because clients depend on it. The profile server adds a third table. Pydantic
  validation failures are routed to the right table by the matched route's tags.
- `profile/` — the profile server, mounted at `/profile/v1`. Upstream answers each request with
  two HTTP calls (`/v1/verify`, then `/v1/account/profile`); both are local here. Fields are gated
  per scope, so a `profile:uid` token learns the uid and nothing else. No avatars and no display
  names exist, so those keys are absent rather than empty — `display_name` answers 204, the same
  answer the reference gives an account that never set one.
- `wellknown.py` — the two discovery documents. The version segments are the trap: Firefox appends
  `/v1` to the auth, OAuth and profile bases and `/1.0/sync/1.5` to the tokenserver base, so none
  of them may carry it already. `pairing_server_base_uri` points at our own origin so a pairing
  attempt fails visibly rather than reaching Mozilla's channelserver.
- Two things the reference does that fxa-lite answers differently, both documented at the routes:
  `/v1/oauth/destroy` cannot revoke an access token (there is no row to delete — it expires within
  `ttl.access_token`), and `acr_values=AAL2` is refused with errno 120 rather than the errno that
  sends a frontend off to a second-factor challenge that does not exist here.
- Verified: 387 tests. `tests/conformance/client.py` grew the relier half of the flow — PKCE,
  scoped-key derivation and a compact ECDH-ES JWE, all written out again from the protocol
  description. `test_sync_flow_recovers_the_oldsync_key` walks password → `kB` → scoped-key-data →
  `keys_jwe` → code → token → decrypt, and checks the recovered key against a derivation done
  straight from `kB` and the account's own `keysChangedAt`. `ruff check` and `ty check` clean.

### Phase 4 — content server / WebChannel ✅ done
Static HTML + vanilla JS (WebCrypto for PBKDF2/HKDF — the browser does the password stretching,
we never see the password). Serve `/`, `/signin`, `/oauth/signin`, `/pair`, `/authorization`,
`/settings`. Message sequence, per `packages/fxa-settings/src/lib/channels/firefox.ts`:

```
fxaccounts:fxa_status  ->  {service, isPairing, context}
                       <-  {capabilities:{engines,...}, clientId?, signedInUser?}
fxaccounts:can_link_account -> {email, uid?}   <- {ok}
fxaccounts:login       ->  {email, sessionToken, uid, verified, verifiedCanLinkAccount,
                            services:{sync:{offeredEngines, declinedEngines}}}
fxaccounts:oauth_login ->  {action, code, redirect, state, scope, offeredSyncEngines,
                            declinedSyncEngines}
```
Envelope: `CustomEvent('WebChannelMessageToChrome', {detail})` where `detail` is
`JSON.stringify({id: 'account_updates', message: {command, data, messageId}})` — a **string** for
Desktop. Replies arrive on `WebChannelMessageToContent`; 500 ms default timeout; always
`requestAnimationFrame` the send *after* attaching the listener.

Two rules that cost days if missed: **omit `keyFetchToken`/`unwrapBKey` from `fxaccounts:login`
on OAuth flows** (`pages/Signin/utils.ts` — they cause intermittent sync disconnects), and
`fxaccounts:login` **must** precede `fxaccounts:oauth_login`. `redirect` is always the sentinel
`urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel`.

Copy structure from `packages/fxa-settings/src/pages/WebChannelExample/index.tsx` (a minimal
working emitter) and the browser-side mock in `packages/functional-tests/pages/layout.ts`.

As built:

- `content/` — one HTML shell, one stylesheet and three ES modules
  (`crypto.js`, `api.js`, `webchannel.js`) driven by `app.js`, which picks the
  view from `location.pathname` the way the reference SPA does. Firefox chooses
  the URLs, so all of them are served: `/` (the email-first entry point
  `identity.fxaccounts.autoconfig.uri` opens), `/signin`, `/oauth/signin`,
  `/authorization`, `/settings` and `/settings/*`, `/pair` and
  `/connect_another_device`, plus `/oauth/success/{client_id}` — a redirect
  `oauth/clients.py` had been registering since phase 3 with nothing behind it.
- `/` therefore belongs to the content server, and the auth server's landing
  JSON now lives only at `/__version__`. Upstream can serve both because those
  are two origins; here there is one.
- No inline script anywhere, which is what lets the shell carry a CSP with no
  `unsafe-inline` — plus `Referrer-Policy: no-referrer`, because the query
  string holds `keys_jwk`, `state` and `code_challenge`, and `Cache-Control:
  no-store`. Assets are served with an ETag and revalidated, so a redeploy is
  picked up without a cache-busting name.
- `app.js` builds every node with `createElement`/`createTextNode`; a test
  asserts no asset contains `innerHTML`, which is what keeps a URL parameter
  from becoming markup.
- There is no "choose what to sync" screen: the page offers back exactly the
  engines `fxa_status` named and declines nothing, which is where upstream
  landed in June 2025 when it dropped the screen too.
- Deliberate gaps, each answered rather than 404'd: `/pair` and
  `/connect_another_device` say pairing needs a channel server, and `/settings`
  says account management lives in the CLI, offering only `fxaccounts:logout`.
- Verified two ways, both under node — the browser crypto is the one part of
  fxa-lite pytest cannot reach directly, and a mistake in it fails as "Firefox
  signs in but never syncs". `tests/js/crypto_kat.mjs` runs `crypto.js` against
  the same vectors that pin `fxa_lite.crypto`, and seals a JWE that the Python
  side opens — the only check that covers the `epk`, the concat KDF's algorithm
  binding and the AAD at once. `tests/js/signin_harness.mjs` runs `app.js`
  against a minimal DOM, a recording WebChannel and a real uvicorn on loopback,
  pinning both rules above (`fxaccounts:login` first; no key material on it for
  OAuth), their mirror image on `fx_desktop_v3`, and the whole flow from typed
  password through to the oldsync key coming back out of `keys_jwe`.
- 428 tests. `ruff check` and `ty check` clean.

### Phase 5 — tokenserver
`GET /token/1.0/sync/1.5`, `Authorization: Bearer <access token>`, `X-KeyID: <kid>`. Verify the
JWT locally against our own JWKS, require the `oldsync` scope, derive `fxa_kid` from the client
state, allocate/lookup the numeric `uid`, mint the tokenlib token. `node` is our own
`/storage` URL. Handle client-state change (keys rotated) by retiring the old sync uid.

### Phase 6 — Sync 1.5 storage
Real HAWK verification this time (id = tokenlib token, key = derived secret, algorithm sha256,
payload hash checked). Endpoints: `GET /info/{collections,collection_counts,collection_usage,
configuration,quota}`, `GET|POST|DELETE /storage/{collection}`, `GET|PUT|DELETE
/storage/{collection}/{id}`, `DELETE /1.5/{uid}`. Headers: `X-Last-Modified`,
`X-Weave-Timestamp`, `X-Weave-Records`, `X-Weave-Next-Offset`, `X-If-Unmodified-Since`,
`X-If-Modified-Since`. Batch upload (`?batch=true` / `commit=true`). Two-decimal-second
timestamps stored as integer milliseconds.

### Phase 7 — real Firefox
Fresh profile, `about:config`:
```
identity.fxaccounts.autoconfig.uri   = https://<host>/
webchannel.allowObject.urlWhitelist  = https://<host>       (origin, no trailing slash)
identity.fxaccounts.allowHttp        = true                 (only if serving plain HTTP)
```
The single-pref form is preferred; the explicit alternative (`identity.fxaccounts.auth.uri`,
`.remote.oauth.uri`, `.remote.profile.uri`, `identity.sync.tokenserver.uri`) is documented in
`resources/fxa-selfhosting/init.sh:143-166` if autoconfig misbehaves.
Reference pref list: `resources/fxa/packages/fxa-dev-launcher/profile.mjs`.

---

## Verification

- `uv run pytest` — KAT suite (Phase 1) plus HTTP-level tests driving the app through
  `httpx.ASGITransport` with `tests/conformance/client.py`, our Python port of `fxa-auth-client`.
  The client must derive credentials independently of the server code so a shared bug can't hide.
- Full-flow test: create account → login(keys=true) → fetch keys → unbundle → `kB` →
  scoped-key-data → build `keys_jwe` → `/v1/oauth/authorization` → `/v1/oauth/token` → decrypt
  `keys_jwe` client-side → assert the recovered oldsync key equals a direct derivation from `kB`.
- Sync-tier test: that access token → tokenserver → HAWK-sign a BSO PUT → read it back.
- `ruff check` + `ty check`.
- Manual: Phase 7, then `about:sync-log` and the Sync panel in `about:preferences#sync`.

## Deliberately out of scope

Email/SMTP entirely, password reset and recovery keys, TOTP/2FA/recovery codes/passkeys,
sign-in unblock and the customs/rate-limit server, subscriptions and payments, push
notifications and Send Tab, QR pairing (the channelserver), device commands, metrics/Glean/Sentry,
the admin panel, and BrowserID (`/certificate/sign` is gone from the reference too).

Send Tab and pairing are the two most likely "actually I do want that" additions later; both are
additive and neither changes the schema decisions above.
