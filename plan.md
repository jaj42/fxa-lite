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

### Phase 1 — crypto core, test-first
Implement `crypto/` and validate against KATs transcribed from:
`packages/fxa-auth-server/lib/crypto/{hkdf,pbkdf2,scrypt,password,butil}.spec.ts`,
`lib/tokens/{token,key_fetch_token,session_token,account_reset_token}.spec.ts`,
`packages/fxa-auth-client/test/{crypto,salt,hawk,bearer}.ts`,
`libs/vendored/crypto-relier/src/lib/deriver/{scoped-keys,driver-utils}.spec.ts`.
Round-trip the JWE against `jweDecrypt` semantics in `fxa-auth-client/lib/crypto.ts`.
**This is the phase that decides whether the whole project interoperates.** Do not proceed on
"looks right" — proceed on byte-equal vectors.

### Phase 2 — accounts API
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

### Phase 3 — OAuth, profile, discovery
`GET /v1/jwks`, `POST /v1/oauth/authorization` (sessionToken-authed, PKCE S256, `keys_jwe`
passthrough, service→scope resolution for `service=sync`), `POST /v1/oauth/token`
(`authorization_code` + `refresh_token`, single-use codes, 15-min expiry),
`POST /v1/account/scoped-key-data`, `POST /v1/verify`, `POST /v1/introspect`,
`POST /v1/oauth/destroy`, `GET /v1/client/{id}`, `GET /profile/v1/{profile,email,uid,display_name}`,
`/.well-known/{openid-configuration,fxa-client-configuration}`.

Collapse the internal `assertion` round-trip (`makeAssertionJWT` → `verifyAssertion`, HS256,
60 s TTL) into a direct call — it exists upstream only because auth and oauth used to be separate
services. Skip PPID, token-exchange, consent ledger, DAU metrics, subscriptions.

### Phase 4 — content server / WebChannel
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
