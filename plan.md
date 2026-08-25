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
- **Support the `fxa-credentials` direct grant.** This reverses the original decision, which put
  it out of scope alongside RFC 8693 token exchange on the reasoning that the code flow is what a
  browser uses. Phase 8 established otherwise, from a packet trace rather than a reading: Firefox
  Desktop completes the code flow, **destroys the refresh token it was just issued**, and mints
  every subsequent access token — including the `apps/oldsync` one Sync runs on — from its
  session token. Without this grant a real browser signs in and then never syncs. Token exchange
  stays out of scope; nothing has been observed asking for it.
- **Implement the JOSE subset rather than depend on `python-jose`** — evaluated at
  `resources/python-jose` 3.5.0 (`018b310d`) and rejected on three counts. It cannot do the half
  that matters: `ECDH-ES` is in `Algorithms.ALL` but excluded from `SUPPORTED`, and both
  `jwe.encrypt` and `jwe.decrypt` gate on `SUPPORTED` (`jose/jwe.py:46-49`, `99-102`), so
  `keys_jwe` raises `JWEError`. It costs three dependencies rather than one, and the wrong three:
  `install_requires` is `ecdsa`, `rsa`, `pyasn1` — pure-Python crypto shipped as the *default*
  backend, `cryptography` only an extra — and `ecdsa` documents itself as not side-channel
  resistant. And the "benefit from the library's evolution" argument, which is the whole reason to
  take a dependency here, does not hold for this one: 3.4.0 (Feb 2025) is where CVE-2024-33663 and
  CVE-2024-33664 were fixed and 3.5.0 (May 2025) is the last release. Phase 9 gives `joserfc` and
  `jwcrypto` — both built on `cryptography` — one bounded look before hardening what we have.

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
UPSTREAM.toml             # what "the reference" is: per checkout, the commit read and the
                          #   paths read from it — `resources/` itself is gitignored
Dockerfile                # multi-stage uv build; runtime carries only /app/.venv
docker-compose.yaml       # one service, one /data volume, published on loopback
.dockerignore             # keeps `resources/` and the deployment secrets out of the image
scripts/
  upstream-diff.sh        # what upstream has done to those paths since we last looked
  docker-smoke.sh         # build the image, bootstrap it, assert it serves and leaks nothing
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
  test_upstream.py        # UPSTREAM.toml still describes the checkouts; skips without them
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
(`authorization_code` + `refresh_token` + `fxa-credentials` — see phase 8, which is where the
third one turned out to be mandatory — single-use codes, 15-min expiry),
`POST /v1/account/scoped-key-data`, `POST /v1/verify`, `POST /v1/introspect`,
`POST /v1/oauth/destroy`, `GET /v1/client/{id}`, `GET /profile/v1/{profile,email,uid,display_name}`,
`/.well-known/{openid-configuration,fxa-client-configuration}`.

Collapse the internal `assertion` round-trip (`makeAssertionJWT` → `verifyAssertion`, HS256,
60 s TTL) into a direct call — it exists upstream only because auth and oauth used to be separate
services. Skip PPID, token-exchange, consent ledger, DAU metrics, subscriptions.

That collapse is what makes the `fxa-credentials` grant nearly free when phase 8 forces it:
upstream the grant means "present an assertion", and the assertion is something the server signs
about a session token it is already holding. With one process the session token can be read
directly, so the direct grant is `SessionClaims.for_session` plus the same
`validate_requested_grant` the authorization route calls, and no assertion is ever constructed.

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

### Phase 5 — tokenserver ✅ done
`GET /token/1.0/sync/1.5`, `Authorization: Bearer <access token>`, `X-KeyID: <kid>`. Verify the
JWT locally against our own JWKS, require the `oldsync` scope, derive `fxa_kid` from the client
state, allocate/lookup the numeric `uid`, mint the tokenlib token. `node` is our own
`/storage` URL. Handle client-state change (keys rotated) by retiring the old sync uid.

As built:

- `tokenserver/__init__.py` — one route. Verification collapses to a local signature check
  (upstream calls FxA's `/v1/verify` or caches its JWKS), and node allocation collapses to a
  constant, because there is one node. What does not collapse is `TokenserverRequest::validate`
  and `update_user`: the rules about `generation`, `keysChangedAt` and the client state are ported
  line for line, including `opt_cmp!`'s "false unless both operands are present" — the asymmetry
  is the point, since a client that has never reported a `generation` must not be locked out by
  one while a client that has reported one may not stop.
- One divergence, documented at the route: fxa-lite **checks `aud`**. Upstream turns that check off
  with a comment saying the ecosystem does not request the right audience; ours mints that audience
  itself in `grant.py`, so the check holds and it is what stops a token issued for another relier
  from being spent here.
- `X-KeyID`'s client state is matched against a base64url regex before decoding.
  `base64.urlsafe_b64decode` *discards* characters outside the alphabet instead of raising, so
  `1234-!!!!` decoded to an empty client state and was accepted — a test caught it. Rust's
  `URL_SAFE_NO_PAD` rejects both stray characters and padding, and so does this.
- `tokenserver/errors.py` — a second error envelope, `{status, errors:[{location,name,description}]}`.
  It is not the accounts API's and must not be tidied into it: Firefox has a separate parser for
  each, and `status` (`invalid-client-state`, `invalid-generation`, `invalid-keysChangedAt`) is
  what tells the client to re-authenticate rather than retry a dead token forever. `app.py` gained
  a handler for it, and routes a 404 below `/token` there too.
- `tokenserver/tokenlib.py` — minting only; the storage tier's reading half lands in phase 6. Three
  encodings are load-bearing and each is a plausible mistake: URL-safe base64 **with** padding
  (unlike every other base64url here), an HKDF salt that is the ASCII of the hex salt string, and a
  derive info ending in the token's own base64 text, which binds the key to the exact id.
- The shared secret is **derived from the OAuth signing key** when `tokenserver_shared_secret` is
  unset. Upstream must configure it because the two tiers are separate deployments that have to be
  told the same string; here they are one process, so there is nobody to agree with, and a secret
  that silently defaults to empty is how Sync fails without a message. Rotating either key costs
  clients one extra token fetch.
- `hashed_fxa_uid` / `hashed_device_id` are keyed with that same secret rather than upstream's
  dedicated `fxa_metrics_hash_secret`: there is no metrics pipeline, but the values still go on the
  wire and into the token, so they still have to be one-way. `hash_device_id`'s upstream parameter
  is named `fxa_uid` and is passed the *already hashed* uid; reproduced as-is.
- `sync_users` is schema v2, and `db.migrate()` now applies ordered steps rather than creating
  everything at once — a phase 4 database upgrades in place. The uid column is `AUTOINCREMENT`
  because SQLite otherwise reuses the largest rowid after a delete, and that uid *is* the storage
  directory. Unlike upstream, whose tokenserver is a separate database keyed on
  `<uid>@<email domain>`, the foreign key here is real: deleting an account takes its Sync data.
- `node_type` answers `"sqlite"`. Upstream's enum is mysql/spanner/postgres and fxa-lite is none of
  them; Firefox reads `id`, `key`, `uid` and `api_endpoint` and ignores the rest.
- Verified: 485 tests. `tests/conformance/client.py` grew tokenlib's *reader* — the half
  `syncstorage-rs` implements, written out from `token/native.rs` — so the token is checked by an
  independent implementation rather than by fxa-lite agreeing with itself, and phase 6's parser has
  a specification to match. Each consistency rule has its own test with the credential hand-built,
  since a real client cannot produce most of those situations. `ruff check` and `ty check` clean.

### Phase 6 — Sync 1.5 storage ✅ done
Real HAWK verification this time (id = tokenlib token, key = derived secret, algorithm sha256,
payload hash checked). Endpoints: `GET /info/{collections,collection_counts,collection_usage,
configuration,quota}`, `GET|POST|DELETE /storage/{collection}`, `GET|PUT|DELETE
/storage/{collection}/{id}`, `DELETE /1.5/{uid}`. Headers: `X-Last-Modified`,
`X-Weave-Timestamp`, `X-Weave-Records`, `X-Weave-Next-Offset`, `X-If-Unmodified-Since`,
`X-If-Modified-Since`. Batch upload (`?batch=true` / `commit=true`). Two-decimal-second
timestamps stored as integer milliseconds.

As built:

- `syncstorage/hawk.py` — the MAC is verified, and this is the first place in the codebase where
  that sentence is true. Pinned against the complete worked example in `web/auth.rs`'s own tests:
  a master secret, a tokenlib id minted from it and two signed requests with their MACs, run end
  to end through signing key → token signature → derived HAWK key → MAC. Host and port come from
  `public_url` rather than the `Host` header, because the client signed the URL the tokenserver
  handed it and that URL is built from `public_url` — reading the request instead would mean any
  proxy rewriting `Host` silently breaks every signature. Upstream reads actix's `ConnectionInfo`
  because it has no `public_url` to consult.
- **The payload hash is checked when the client sends one, which upstream does not do** — neither
  syncstorage-rs nor the Python server before it. The MAC covers whatever `hash` the client
  claimed, not the body that arrived, so without this the body is unauthenticated. A correct HAWK
  client computes it correctly by definition; one that omits it is still served, with its body
  uncovered, which is what the specification says and what every client relies on.
- `syncstorage/errors.py` — the *third* error envelope: a bare JSON integer, the Weave code, as
  the whole body. `ResponseError::error_response` keeps the descriptive form commented out for
  Sync 1.1 compatibility, so this is not an oversight to tidy up. `app.py` gained a handler, and
  routes a 404 below `/storage` there too, the way `render_404` does.
- `syncstorage/store.py` — schema v3 (`sync_collections`, `sync_user_collections`, `sync_bso`,
  `sync_batches`, `sync_batch_items`), all hanging off `sync_users.uid`, so a key rotation's new
  uid gets an empty directory and the old records stay where nothing will try the new key on them.
  Collection id 0 is the tombstone, seeded by the migration, which is how deleting a collection
  moves the *storage* timestamp with nothing left to carry one.
- One request is one transaction, one timestamp, quantized to a hundredth of a second before
  anything is written. **A write that cannot move its collection's timestamp forward is refused**
  (503 + `Retry-After: 10`), which is upstream's `lock_for_write`. It fires far more often here
  than upstream — an in-process SQLite write takes microseconds where a MySQL round trip takes
  milliseconds — but the invariant it protects is the one `?newer=` polling rests on, and
  inventing a different answer would mean a behaviour no client has been tested against. The
  conformance client waits out the tick and retries, as a real client does.
- Two upstream behaviours deliberately *not* reproduced, each noted at its method: `do_append`
  forgets to filter on the BSO id, so re-sending one record in a batch rewrites every record
  already staged in it; and a storage wipe leaves open batches behind, so committing an id opened
  beforehand resurrects what the wipe removed. Both are bugs rather than protocol.
- Reproduced *because* they are protocol, however odd: a `put` carrying neither payload nor
  sortindex does not move `modified`; a batch item with no ttl commits with `MAX_TTL` as an
  absolute instant rather than as a duration, a different "forever" from the un-batched path's;
  `get_bso_ids` pages with a bare row count where `get_bsos` pages with a timestamp token; and
  `/info/collections` is served on an expired credential, matched on all five path segments so
  that the BSO `collections` in collection `info` is not.
- `/info/configuration` takes no credential — upstream's handler takes neither a token nor a
  database connection. The limits are constants a client needs before it can decide how to split
  an upload, and requiring a token to read a published constant only produces clients that cannot
  ask. Limits are fixed rather than configurable: they are what every Firefox has been written
  against, and a household server has no business being the one place in the ecosystem where a
  client meets a limit it has never seen. `/info/quota` reports a null limit for the same reason —
  a number would be a promise the filesystem, not this server, decides whether to keep.
- Timestamps go out as JSON floats rather than upstream's arbitrary-precision numbers, so `0.00`
  reads as `0`. The value is identical and clients compare timestamps, not their spelling;
  `X-Last-Modified`, which is a string, always carries both decimals.
- Verified: 604 tests. `tests/conformance/client.py` grew a storage client that builds the
  normalized HAWK string itself, from the specification rather than from `fxa_lite.syncstorage` —
  so every signature in the HTTP tests is checked by an independent implementation.
  `test_the_whole_stack_composes` runs password → `kB` → oldsync key → access token →
  tokenserver → HAWK-signed PUT → read back, which is the test that fails if any two tiers
  disagree about what they hand each other. `ruff check` and `ty check` clean.

### Phase 7 — pin the upstream commits ✅ done

`resources/` is gitignored and untracked, so nothing in this repository records what "the
reference" *is*. Every "verified against the reference" claim above, and every constant in
**Protocol constants**, is true of one commit and unverified against any other; if those
checkouts are deleted the provenance goes with them. This is fifteen minutes of work and it
blocks phase 12, so it goes first.

- `UPSTREAM.toml` at the repo root — tracked, unlike `resources/`. Per checkout: the clone URL,
  the commit fxa-lite was read against, its date, and one line on what we took.

  ```
  mozilla/fxa                      b522aa57  2026-08-22  protocol, KATs, accounts/OAuth/profile
  mozilla-services/syncstorage-rs  3f0f985c  2026-08-21  tokenserver, Sync 1.5, tokenlib, HAWK
  jackyzy823/fxa-selfhosting       200626f1  2026-08-21  what self-hosting the real thing costs
  michielbdejong/fxa-self-hosting  2343760c  2016-05-13  historical only — ten years stale
  mpdavis/python-jose              018b310d  2025-05-28  evaluated, not adopted — see above
  ```

- Per repo, the **paths we actually read**, not the repo. `mozilla/fxa` is a monorepo whose churn
  is overwhelmingly subscriptions, Glean and the settings SPA, none of which we implement. The
  files that matter are already enumerated throughout this plan — `lib/crypto/*`, `lib/tokens/*`,
  `lib/oauth/*`, `lib/routes/auth-schemes/hawk-fxa-token.js`, `crypto-relier/…/scoped-keys.ts`,
  `fxa-auth-client/lib/*`, `fxa-settings/src/lib/channels/firefox.ts`; syncstorage-rs's are
  `tokenserver-auth/src/token/native.rs`, `syncserver/src/tokenserver/*`,
  `syncserver/src/web/auth.rs`, `syncstorage-*/src/db/*`. Collecting that list into the file is
  what makes the diff readable instead of two thousand irrelevant commits.
- `scripts/upstream-diff.sh` — per entry,
  `git -C resources/<repo> log --oneline <pinned>..origin/main -- <paths>`.
  A log, not a diff: a protocol change shows up as a commit touching `lib/crypto/` and nothing
  else does.
- Bump a pin only together with the code or the note that answers its diff, so the file always
  means "fxa-lite is current with respect to this commit" and never "this is where we last looked".
- A test asserting every path in `UPSTREAM.toml` exists in its checkout, skipped when `resources/`
  is absent. Upstream renames files; a stale path makes the diff *empty*, which reads as "nothing
  changed" — the one failure mode this file cannot survive.

As built:

- `UPSTREAM.toml` — five `[[repo]]` entries, fifty paths (phase 9 added two more, for the
  libraries it evaluated). Each entry is `dir` (the directory
  under `resources/`), `url`, `branch`, the full 40-character `commit`, `date`, one line of
  `took`, and `paths`. Branch is per repo and not an afterthought: only `mozilla/fxa` is on
  `main`, the other four are still on `master`, so the `origin/main` in the sketch above would
  have compared four of the five against nothing.
- The path list is longer than the sketch because it is the list that was *read*, not the list
  that was quoted. **Protocol constants** cites the files a constant came from; a route handler
  matched by shape leaves no citation but is exactly as much of a dependency. So the routes
  fxa-lite serves are listed alongside the crypto — `lib/routes/{account.ts,session.js,
  devices-and-sessions.js,emails.js,oauth/}`, `lib/devices.js`, the profile server's routes and
  its errno table, `config/dev.json` for the three browser clients, and
  `fx-sync-channel.js` for the fields the browser end of the WebChannel requires.
- `scripts/upstream-diff.sh` reads the manifest through `tomllib` rather than restating the
  paths, since two copies of a path list is the same rot the file exists to prevent. Fetches by
  default (a stale remote-tracking ref answers the wrong question), `--no-fetch` to work
  offline, repo names to narrow. Exit 1 when an entry has commits to show so CI can ask; exit 2
  when an entry cannot be read, including a repo name that matches no entry — silently logging
  nothing is how a typo becomes "upstream is current".
- `tests/test_upstream.py` — 26 tests, all skipping cleanly without `resources/`. Paths are
  checked at **two** commits, because the two catch different things: at the pin, so the
  manifest honestly describes the tree it was read from; and at `origin/<branch>`, which is the
  check that matters. A rename shows up in the log exactly once, as the commit that renamed it,
  and is invisible in every log taken after the pin is bumped past it — so the assertion has to
  fire at the moment of the bump, which is the last moment it is cheap to fix.
- Also checked: the pin resolves in the clone and its `%cs` matches the recorded date, `origin`
  matches the recorded URL, no path is nested inside another listed path, and — the one that
  closes the gap rather than guarding it — every checkout under `resources/` appears in the
  manifest. A sixth clone somebody read from and did not record is precisely the provenance
  hole this phase exists to fill.
- Verified: 630 tests, `ruff check` and `ty check` clean, and `upstream-diff.sh` reports all
  five entries current. One unrelated fix on the way past:
  `test_a_second_write_inside_the_same_hundredth_conflicts` raced its own precondition — an
  in-process PUT takes a couple of milliseconds, so two of them shared a hundredth most of the
  time but not all of it, and the test failed about one run in three. It now freezes the
  storage app's clock instead of hoping, because a test that asserts a conflict has to cause one.

### Phase 8 — real Firefox ✅ done
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

**Firefox for Android (Fenix), which is the other half of a household.** There is no
`about:config`; the equivalent is the secret menu — Settings → About Firefox → tap the logo five
times → Settings → **Sync Debug** — and two text fields, named *Custom Mozilla account server*
(*Custom Firefox Account server* in older builds) and *Custom Sync server*. With everything on one
origin they are:

```
Custom Mozilla account server = https://<host>
Custom Sync server            = https://<host>/token/1.0/sync/1.5
```

Note the asymmetry, which is the thing a person gets wrong: the account field is an **origin**,
from which the app reads `/.well-known/fxa-client-configuration` exactly as desktop does, while
the sync field is a **full tokenserver URL including `/1.0/sync/1.5`** — upstream those are two
deployments and the field predates discovery. `resources/fxa-selfhosting/init.sh:184` and its
README:103 are the reference for both spellings. Fenix is already registered as a client
(`a2270f727f45f648`, `oauth/clients.py:39`) with `<public_url>/oauth/success/<client_id>` among
its redirects, and the content server already serves that path, so nothing in fxa-lite should need
changing — which is a hypothesis, not a result, until a phone has synced.

Four things this phase has to establish, because the docs cannot be written from a reading of the
source and each one is a sentence in phase 12. **None of the four were answered** — Android syncs
without them being settled, so they went to phase 12 unanswered rather than blocking this one; see
the closing note at the end of the phase:

- whether the *Custom Sync server* field is needed at all, given that our discovery document
  already advertises `sync_tokenserver_base_url` — if the app prefers discovery when the override
  is blank, the honest instruction is one field, not two;
- what the fields do to an already-signed-in profile: whether they require signing out first, and
  whether the app restarts;
- whether *Use New React Mozilla Account page* changes which content-server path the app opens,
  since our shell answers a fixed table of paths (`content/__init__.py:PAGE_PATHS`) and a path
  outside it is a 404 in a web view;
- Firefox for iOS: registered as `1b1a3e44c54fbb58`, but whether a shipping build can be pointed
  at a custom server at all is unknown. Establish it or record that it cannot, rather than leaving
  the README silent on a client the code claims to support.

**Established so far** (desktop, Firefox on Linux, one origin on `http://localhost:9000`):

- **A LAN IP over plain HTTP cannot work, and the reason is not FxA.** The sign-in page derives
  the password with `crypto.subtle`, which browsers expose only in a secure context. `localhost`
  and `127.0.0.1` qualify; `http://192.168.x.x` does not, and the page dies at
  `crypto.subtle is undefined` after everything else has gone right. Serving a household off a
  LAN address therefore needs real TLS — phase 11 has to provide it, not treat it as optional
  polish. Upstream's own dev config is `http://localhost:9000` (`fxa-dev-launcher/profile.mjs`),
  which is why this never shows up in their instructions.
- **HTTPS-Only mode silently upgrades the request** before it leaves the browser, and the server
  sees a TLS ClientHello on a plaintext socket — uvicorn logs `Invalid HTTP request received`
  and no access-log line at all, which reads like a protocol bug and is not one. Loopback is
  exempt from the upgrade; a LAN IP is not. The README has to say this.
- **`grant_type=fxa-credentials` is mandatory.** See the amended decision above. The trace:
  `login` → `scoped-key-data` → `keys` → `authorization` → `token` all succeed, and then Firefox
  immediately calls `/v1/oauth/destroy` on the refresh token it was just handed and switches to
  the direct grant for `profile` and for `apps/oldsync`, retrying on a loop when refused. Setting
  `identity.fxaccounts.oauth.enabled = true` changes nothing — on this build the pref does not
  exist, so the behaviour is not configurable away.
- **`GET /v1/account/attached_clients` is missing** and Firefox polls it throughout the session.
  It was not in the plan at all: the reference merges devices, sessions and authorized OAuth
  clients into one flat list (`lib/routes/attached-clients.js`, `ConnectedServicesFactory`), and
  every input already exists here. There is a simpler sibling, `GET /account/attached_oauth_clients`.
- **A batch commit that carries records answered 503.** Firefox uploads history as ~17 staged
  POSTs and a commit, and puts records in the commit request too. `_post_batch` lands the batch
  (which stamps the collection at `now`) and then calls `post_bsos` for the carried records,
  whose first act is the `check_write` guard — so the request conflicted with the timestamp its
  own commit had just set, and history never landed. Two things hid it: every batch test commits
  with an empty body, and the conformance client retries a 503, so the bug's only symptom in a
  green test run was an extra round trip. `post_bsos` now takes `stamped=True` on that one path.
- **One divergence found on the way past**: `_refresh_token_grant` widened a trusted client's
  scope to `scope ∪ client.allowedScopes`, omitting `TRUSTED_CLIENT_ALLOWED_SCOPES`
  (`openid`, `profile`, `email`, `profile:subscriptions` — `lib/oauth/grant.js`).
  `validate_requested_grant` had it right; only the refresh path did not.

- **Debugging this needed a tool that did not exist**, and building it three times as a throwaway
  proxy is how you learn to build it once. An access log line says a request was a 400; every
  question in this phase was "which field", and the answer is two lines of JSON that never reach
  the terminal. `tracing.py` is that proxy made permanent: a pure-ASGI middleware, installed
  outermost, that renders each request and response at `DEBUG` and costs one `isEnabledFor` call
  otherwise. It is safe to ship enabled-by-config because it redacts by key name before writing —
  `authPW`, session and key-fetch tokens, access and refresh tokens, `keys_jwe`, `bundle`,
  `unwrapBKey`, `code`, Sync `payload` — down to a prefix and a length. The prefix is what lets
  two log lines be matched against each other, which is the only reason to want the value at all.
  A value of 16 characters or fewer collapses entirely, because eight characters of a short
  secret is most of it. The `Authorization` header keeps its scheme (`Hawk` vs `Bearer` is
  frequently the bug) and loses its credential. Phase 10 should treat `SECRET_KEYS` as an audit
  item: the redaction is exactly as good as that list, and a key added to a route without being
  added there is a credential written to a file.

**Done in this phase.** Firefox Desktop signs in and syncs against fxa-lite, end to end:
tokenserver, `info/collections`, `info/configuration`, `meta/global`, `crypto/keys`, and uploads
of clients, prefs, tabs, bookmarks, addons and history. Three code changes were needed and all
three came from the trace rather than from reading — the `fxa-credentials` grant, the batch-commit
conflict, and the refresh-grant scope divergence — plus `tracing.py` and the README's
*Pointing a browser at it* and *Debugging a client* sections.

**`GET /v1/account/attached_clients` and its sibling are done.** `auth/attached_clients.py` is a
transcription of `ConnectedServicesFactory`, keyed on the two pointers a device record carries —
its `sessionTokenId` and its `refreshTokenId` — so one browser is one row rather than three. Notes:

- The merge is a **pure function** taking the three lists, which is what lets the reference's own
  fixture (`attached-clients.spec.ts`, "creates a merged list of all the things attached to the
  account") be transcribed as a KAT: six rows, each field attributed to whichever of the three
  sources upstream lets win. That fixture is the specification — the rules are all precedence
  (a device names itself, a grant names an unnamed device, a session blanks the scope) and none
  of them are derivable from the route's response schema.
- **Access tokens cannot appear in the list.** Upstream enumerates them from a table and folds
  each client holding one but no refresh token into a row of its own; here an access token is a
  JWT with no server-side row, so there is nothing to enumerate. A client that holds only an
  access token is invisible until it takes a refresh token or registers a device.
- **A grant and a device are never merged here**, because `/account/device` is session-authed and
  our device rows have no way to name a refresh token. A Sync sign-in is therefore two rows, not
  one. The `refreshTokenId` column and the merge path for it are kept, since upstream's rule is
  what a mobile client would need if that ever changes. *(It changed, later in this same phase:
  the mobile pass made `/account/device` refresh-token-authed too, and a Fenix sign-in is one row.
  The merge path was already right and needed no edit — see "The Fenix half, started" below.)*
- `createdTimeFormatted`/`lastAccessTimeFormatted` are `""` and `location` is `{}`: no localizer,
  no geo-IP. The keys stay because `attachedClientsDefaults` has them, and their only consumer is
  a settings UI fxa-lite does not serve.
- `attached_oauth_clients` skips the factory rather than stubbing two of its three inputs out and
  discarding thirteen of its fifteen fields, which is what upstream does.
- `UPSTREAM.toml` gained `lib/routes/attached-clients.{js,spec.ts}` and
  `packages/fxa-shared/connected-services`. 743 tests, `ruff check` and `ty check` clean.

**`POST /v1/account/devices/notify` is done, and it answers 403.** The question was what a server
with no push should say; both candidate answers turned out to be upstream's own, and the trace's
premise ("a 404 leaves Firefox retrying") turned out to be wrong — the caller does not retry, or
even wait.

- What the route is *for*: after uploading the `clients` collection Sync asks the server to wake
  every other device so it picks the change up sooner
  (`clients.sys.mjs:_notifyCollectionChanged` → `FxAccountsClient.notifyDevices`). The promise is
  deliberately not awaited and its rejection is logged, so no answer here can break a sync.
  **Send Tab does not come through this route**: current Firefox delivers commands with
  `POST /account/devices/invoke_command` and the target *polls* `/account/device/commands` — push
  is only the nudge. That is the route to implement if Send Tab is ever in scope, and it can be
  honest about it, because its response reports `enqueued` and `notified` separately.
- Upstream answers `200 {}` when notifications are on — *including* when `push.sendPush` throws,
  which it catches and logs — and 403/errno 202 when `deviceNotificationsEnabled` is false. So a
  200 is not a lie the protocol can detect (the response schema is the empty object and claims
  nothing about delivery), but it is still a lie, and the 403 is a description of fxa-lite that
  happens to be exactly true. errno 202 is in the client's own table
  (`auth-errors.js: FEATURE_NOT_ENABLED`) where a 404's errno 116 is only "unknown endpoint". The
  one asymmetry: upstream's switch is temporary by design ("in case problems with the client logic
  cause server overload"); ours is permanent.
- **Which is why the answer must not carry `retryAfter`, and this is the finding worth keeping.**
  Upstream's `featureNotEnabled` puts `retryAfter: 30` in the body *and* a `Retry-After` header.
  Both are load-bearing in Firefox: `HawkClient._constructError` reads the header and notifies
  `fxaccounts:backoff:interval` on any status, and `hawkclient.request` throws the parsed body
  whenever it carries an `error` key — which this envelope always does — so
  `FxAccountsClient._request` caches it as `backoffError` and rejects **every** FxA request until
  the timer expires. Firefox notifies on every sync, so a permanent 403 spelled upstream's way
  would have stalled the whole account client on a timer that never stops being refreshed.
  `errors.feature_not_enabled` now defaults `retry_after` to `None`, with the reasoning at the
  factory rather than at the one call site.
- The payload is validated first, as it is upstream (hapi validates before the handler runs), so a
  client bug reads as one instead of as a disabled feature. Both joi alternatives are kept,
  including the rule that `excluded` belongs only to the `to: "all"` branch. The `payload` object
  is not validated against `docs/pushpayloads.schema.json`: that schema describes what a
  *delivered* push may contain, and nothing here delivers one.
- **A provenance gap this opened, which phase 7's rules cannot yet close.** Three of the facts
  above are about the *browser*, not the server — `services/sync/modules/engines/clients.sys.mjs`,
  `services/fxaccounts/FxAccountsClient.sys.mjs` and `services/common/hawkclient.sys.mjs` — and
  they were read at `mozilla/gecko-dev` HEAD on 2026-08-24, unpinned, because there is no
  mozilla-central checkout under `resources/` and cloning one to read three files is not a trade
  worth making. `UPSTREAM.toml` therefore does not describe them. Every phase-8 finding so far
  came from a packet trace, which is its own evidence; these came from a reading, which is not. If the
  browser side is read again for anything load-bearing, a sixth entry — sparse, on those three
  paths — is the honest fix.
- `UPSTREAM.toml` gained `devices-and-sessions.spec.ts` and `packages/fxa-auth-server/config/index.ts`
  (read narrowly, for what `deviceNotificationsEnabled` *means*), and the `mozilla/fxa` pin moved
  to `f87b36d0` (2026-08-24). Widening the path list is what raised the diff, and it answers to
  nothing: across every path fxa-lite reads, the only change since `b522aa57` is the removal of a
  mailer config key and the `canSend` flag behind it. There is no mailer here.

**`/favicon.ico` no longer 404s.** The shell now names an icon in a `<link>`, which is what stops
the browser asking for the well-known path at all, and the path is served too — as SVG, since the
extension is a convention and the `Content-Type` is the declaration. Cosmetic, but the log is the
instrument this phase is read with, and a 404 in it should mean something.

755 tests, `ruff check` and `ty check` clean.

**The Fenix half, started — and two routes were missing.** With TLS in front of it (phase 11,
landed early for exactly this reason) Firefox for Android loads the sign-in page, completes the
whole flow — `login?keys=true` → `scoped-key-data` → `keys` → `authorization` → `token`, every one
a 200 — and says *Signed In*. The account is then not active, and the trace says why in its last
two lines. Neither was configuration; both were routes fxa-lite did not serve.

- **`POST /v1/destroy` was a 404.** The mobile client revokes tokens through the pre-RFC-7009
  spelling, not `/v1/oauth/destroy`. Upstream exports both from one handler
  (`lib/routes/oauth/destroy.js`), and they differ only in how the payload names the token:
  `/oauth/destroy` takes one opaque `token`, `/destroy` takes exactly one of `access_token` (or
  `token`, which it renames), `refresh_token`, or `refresh_token_id`. Two divergences in ours, both
  consequences of earlier decisions: an access token is a no-op, because phase 3 left no
  access-token table to delete a row from and upstream's `invalidToken` would then be the answer
  for *every* access token; and an already-revoked refresh token is a success, matching
  `/oauth/destroy` and RFC 7009 §2.2.
- **`POST /v1/account/device` answered 401, and this is the one that mattered.** The phone
  authenticates device registration with `Authorization: Bearer <64 hex>` — the **OAuth refresh
  token itself**, unprefixed, because it never holds a session token at all. `credentials.py`
  rejected it on purpose ("`Bearer <hex>` with no prefix is an OAuth refresh token, a different
  credential entirely"), which was right about what it is and wrong about what to do with it.
  Upstream lists three strategies on every `/account/device*` route — `sessionTokenBearer`,
  `sessionToken`, `refreshToken` — and the third is `lib/routes/auth-schemes/refresh-token.js`:
  hash the token to its id, look it up in the OAuth table, require the client to be registered and
  public, and require the grant to be entitled to manage devices at all (its client on
  `config.oauth.deviceManagementClientIds`, or its scopes including oldsync). That list is copied
  verbatim into `oauth/clients.py` — including the two Android builds fxa-lite does not register
  as clients of its own, because it is an authorization rule and not a registry, and trimming it
  to our cast would silently change the rule.

What that scheme brings with it, none of which is optional once a device can be owned by something
other than a session:

- **`devices.refresh_token_id` needed the unique index its session-token sibling always had**
  (schema v4). Android sends no device id, so the server has to find the row that token already
  owns; without the lookup every reconnect leaves another orphan, and the device list is what
  Send Tab delivers to.
- **`lastAccessTime` for a mobile device comes from its refresh token**, since it has no session
  token to read one off and the device row itself never moves. Upstream says so in as many words
  in `/account/devices`.
- **Destroying a device revokes the refresh token**, as `devices.destroy` does through
  `oauthDB.removeRefreshToken`. Disconnecting has to end the connection, and for a mobile client
  the refresh token *is* the connection.
- **A device with no name is named after its OAuth client**, and one registered by a refresh token
  is `mobile` whatever the User-Agent says (mozilla/fxa#449) — a phone may send no `User-Agent`
  worth reading, and "Fenix" beats "".
- The note two sections up — "a grant and a device are never merged here, because
  `/account/device` is session-authed and our device rows have no way to name a refresh token" —
  is now wrong, and pleasantly so: a Fenix sign-in is one row in `attached_clients`, not two. The
  merge path was already there and needed no change.

`errors.Errno` gained 166, `NOT_PUBLIC_CLIENT` — the *auth* tier's spelling of a name the OAuth
tier already had at 116. Two numbers, one sentence; upstream has both.

**`SECRET_KEYS` was checked, as the tracing note above says it must be** whenever a route adds a
field. `/v1/destroy` names four: `access_token`, `refresh_token` and `token` were already there,
and `refresh_token_id` is deliberately not added. It is a SHA-256 of the token and cannot be
spent — upstream hands it out to any session holder, as `refreshTokenId` in
`/account/attached_clients` and as `jti` from `/introspect`. What it *can* do is revoke, so a log
is a revocation capability and not an access one, which is the same trade upstream already makes.
The refresh token arriving in an `Authorization` header is covered by `render_authorization`,
which keeps the scheme and eight characters — visible in the trace that started this section.

**And with those two, Android syncs.** Nothing else was missing: device registration was the last
thing between "Signed In" and an active account, and the routes this phase kept expecting to need
next were never asked for. `GET /account/device/commands` in particular is on upstream's
refresh-token list and mobile is said to poll it, and it had not been requested once — which read
at the time as the phase's own rule vindicated rather than as a gap. ~~Send Tab is the feature
that would ask, and it is not in scope.~~ **That last sentence was wrong, and a longer run of the
phone proved it — see "The command queue that is not there" below.** The rule survives the
correction, and so does its point: what changed is that the trace ran long enough to ask.

830 tests, `ruff check` and `ty check` clean.

**What the phase closes on, and what it hands to phase 12.** Both browsers sign in and sync:
Firefox Desktop on Linux, and Firefox for Android against the same origin over TLS. That is the
bar this phase set, and it is met. Two things it hoped to establish are not established, and
neither is a code question — they are sentences the README needs and a phone or a fresh profile
is the only way to write them:

1. The desktop pass has never been run on a **fresh profile** against a clean database.
   Everything above was observed on a profile that had already failed several sign-ins, so the
   happy path has been
   seen in recovery, not from zero. This is also what would confirm `attached_clients`: answering
   200 is not the same as Firefox being satisfied with what is in the answer, and the trace is the
   only place that shows the difference. The two `GET /storage/meta/global` 404s at the top of a
   first sync are not a defect and should stay: an absent BSO is Weave code 0, and Firefox reads
   the 404 as "this is a fresh server", wipes it and uploads `meta/global` and `crypto/keys`. It
   asks twice because `_remoteSetup` re-fetches after `_freshStart`. On a fresh-profile run the
   whole pair should appear once and never again — which is a prediction, and the reason to make
   the run.
2. **The four questions at the top of this phase are still unanswered**, and they are phase 12's
   problem now rather than this one's. Android syncs, which is what phase 8 owed; what nobody
   wrote down on the way is whether *Custom Sync server* is needed alongside the account-server
   field or whether discovery covers it, what the fields do to an already-signed-in profile,
   whether *Use New React Mozilla Account page* moves the app off the paths `PAGE_PATHS` serves,
   and whether Firefox for iOS can be pointed at a custom server at all. The first three are one
   session with the phone in hand; the fourth may well end in "it cannot", which is a documented
   answer and not a failure. **iOS has not been attempted**, and the README should not imply
   otherwise merely because `1b1a3e44c54fbb58` is in the client registry.

   **This is what decides the order of the remaining phases.** Phase 10 opens with "the code is
   complete… so there is a fixed target to audit", and the mobile pass is the most likely source
   of new routes — desktop produced three code changes from a trace after six phases of reading.
   Auditing, then adding routes, then re-auditing is the worse sequence, so the argument is to
   pull phase 11's proxy work forward far enough to point a phone at fxa-lite and close this
   phase, rather than to defer mobile past the audit. If that trade is refused, the honest
   alternative is to split the phase in the plan — 8a desktop, done; 8b mobile, after 11 — rather
   than leave it looking half-finished.

   **How it actually went, recorded because the prediction was half right.** Phases 9, 10 and 11
   all landed before a phone was pointed at anything, and the mobile pass then did exactly what
   this paragraph said it would: two new routes, a new auth scheme and a schema migration, all
   after the audit. That diff has now been re-read against phase 10's own categories — the
   **Addendum** at the end of `AUDIT.md` — which is the small job this paragraph was arguing for,
   and it found nothing to fix. One assertion about control flow became a test on the way past:
   the schema-v4 unique index cannot be reached by a second write, because the device-conflict
   check refuses it first.

**The command queue that is not there — `GET /account/device/commands`, which was a 404.** Once
the phone had run for a while against fxa-lite it started polling
`GET /v1/account/device/commands?index=1` with its refresh token, and got errno 116, "unknown
endpoint". Phase 8 had closed by saying the route had not been requested once and that only Send
Tab would ask; the first half was a true observation of a short trace and the second half was a
guess, and Fenix polls the queue whether or not anything has ever been sent to it.

- **What the route is.** Commands do not travel by push. The sender enqueues with
  `POST /account/devices/invoke_command`, push is only a nudge, and the target polls here; the
  handler reads the queue with `pushbox.retrieve`. fxa-lite has no pushbox and does not serve
  `invoke_command`, so the queue is not momentarily empty — it does not exist.
- **The answer is 403/errno 202,** for the third time in this file and by the same argument.
  Upstream has a configuration that means exactly what fxa-lite means: with
  `config.pushbox.enabled = false` every pushbox method rejects with `featureNotEnabled`, so this
  route 403s and nothing else in the device API moves. The `retryAfter` is absent as always —
  more pressingly here than on notify, because this is a route mobile *polls*, and a permanent
  timer refreshed on every poll would stall the whole account client.
- **The other switch would have been the wrong one to copy.**
  `oauth.deviceCommandsEnabled = false` reaches further than its name: it also 403s
  `GET /account/devices` for a refresh-token caller, on the reasoning that "the only reason a
  device calls this endpoint is to get a list of other devices it can send commands to". Android's
  device list has to keep answering, so the pushbox switch is the one that describes us.
- **The rejected alternative was `200 {"index": 0, "last": true, "messages": []}`** — what an
  empty queue looks like, and not false, since nothing is pending and nothing can be. It loses on
  the same ground the 200 lost on notify: it is the answer that never changes, and it spends the
  client's polls saying "ask again" instead of saying why. errno 202 is in the client's own error
  table; errno 116 is not an answer about this feature at all.
- **`index` and `limit` are declared and unread.** The query validation is upstream's
  (`limit` 0–100), so a malformed one is still the 400 it has always been rather than a 403 about
  the feature. What is missing is the queue, not the vocabulary. The unknown-device check comes
  first for the same reason it does upstream: a caller with no device record has asked about a
  queue that could not have existed even here.

`invoke_command` is still a 404 and Send Tab is still out of scope — but the two are one feature,
and if the sending half is ever answered it should be answered in the same voice as this one.
838 tests, `ruff check` and `ty check` clean.

### Phase 9 — harden `crypto/jose.py` ✅ done

The "don't roll your own crypto" instinct is right, and its target is smaller than it looks.
`crypto/hkdf.py`, `onepw.py`, `tokens.py` and `scoped_keys.py` are FxA protocol derivations — no
library implements them and none ever will; what makes them safe is the phase 1 KAT suite. The
whole exposure is `crypto/jose.py` (418 lines), and only two parts of it are our own crypto: RS256
sign/verify (~90 lines) and compact JWE ECDH-ES+A256GCM (~150). The rest is JWK plumbing over
`cryptography`.

**First, timeboxed: `joserfc` and `jwcrypto`.** `python-jose` is already answered (see *Decisions
already made*) but that answer does not transfer — both of these build on `cryptography` rather
than shipping their own, so the dependency objection does not apply, and both are expected to
implement ECDH-ES. Two questions decide it, and a "no" to either ends the look:

- Does it do RS256 **and** compact ECDH-ES+A256GCM against `tests/vectors/` unchanged?
- Can `alg` be pinned to one value at the call site? fxa-lite rejects `alg: none` by construction;
  an allow-list *argument* is a thing a later edit widens by accident.

Expect no, for a reason that is about timing rather than quality: `jose.py` is written, pinned by
vectors, and interoperating across six green phases. The case for a library is strongest before
the code exists; afterwards it is a rewrite of the most delicate file in the project against
modest upside. The one argument that survives that is the one worth the hour — a library gets
patched when a JOSE parsing CVE lands, and this file does not. Record the outcome either way.

**Then the actual work, which is needed whichever way that goes**: the coverage a library would
have bought is adversarial, not fewer lines. `jose.py` is today pinned by positive vectors —
RFC 7518 App. C for the concat KDF, RFC 7516 App. A.1 for the AEAD framing — and every path
through it that a hostile input takes is untested.

- Negative tests on every JWT parse path: `alg: none`; `alg` swapped to HS256 with the public key
  as the HMAC secret; unknown `kid`; missing `exp`; `exp`/`iat` as strings; five segments; zero
  segments; a megabyte of header.
- The same for JWE: `epk` on the wrong curve; `epk` off-curve (the invalid-curve attack —
  `cryptography` rejects it, so assert that it does); tampered AAD; tampered tag; `enc` swapped;
  a `zip` we do not support; an oversized body (python-jose's own 250 KiB cap is a fair precedent).
- The RS256 vectors from RFC 7515 App. A.2, which we do not currently have.
- `hypothesis` round-trip properties over both.

Delete `encrypt_jwe_dir` while the file is open: it is referenced only by `tests/test_jwe.py` and
nothing on the wire. If a library *is* adopted after all, the **Dependencies** section above stops
being true and needs saying so.

This is the audit's largest single input, which is why it lands before phase 10 rather than after.

As built:

- **The library question came back "yes" to both, which is not what this plan expected.**
  `joserfc` 1.7.4 and `jwcrypto` 1.5.8, evaluated from PyPI and pinned in `UPSTREAM.toml` at the
  releases that were read. Both sign and verify RS256 that `jose.py` accepts and vice versa; both
  do compact `ECDH-ES`+`A256GCM` that `decrypt_jwe` opens, and both open ours — cross-decrypted
  in each direction, against `tests/vectors/jose.json` unchanged. Both take `algorithms=` /
  `algs=` per call and enforce it. Both refuse `alg: none` and the HS256-with-the-public-key
  confusion *with the argument omitted*, which is the failure mode the question was really
  about. `joserfc` costs exactly one dependency and it is `cryptography`; `jwcrypto` adds
  `typing_extensions` as well. So the objection that answered `python-jose` does not transfer,
  and neither does its conclusion.
- **Not adopted anyway, and the reason is smaller than "timing".** Counting what is actually
  exposed: nothing in `src/` decrypts a JWE. The browser seals the `keys_jwe` in
  `content/assets/crypto.js`, the relier opens it, and the auth server stores the blob and echoes
  it back — `encrypt_jwe_ecdh_es` and `decrypt_jwe` have no caller outside `tests/`. The whole
  hostile-input surface a library would take over is `verify_jwt` plus `decode_jwt_header`, about
  90 lines, reached from three `Authorization:` headers. A library would not have removed the JWE
  code, because that code's job is to be the oracle `crypto.js` is checked against, and no Python
  library can be the oracle for the JS that ships to the browser. "A library gets patched when a
  parsing CVE lands" is the argument that survives, and it is worth less against 90 lines that
  accept one algorithm than it looked worth against 418. Revisit if `jose.py` ever grows a second
  algorithm — that is the change that flips this.
- The **Dependencies** section stands: `fastapi`, `uvicorn[standard]`, `cryptography`.
  `hypothesis` is new in the dev group.
- `jose.py` hardened where the audit will look. Length caps first, because they bound how much
  unauthenticated work a request can ask for before anything is verified: `MAX_JWT_LENGTH` 8 KiB
  (a real access token with ten scopes is under 2 KiB — there is a test asserting the cap has
  room), `MAX_JWE_LENGTH` 250 KiB after python-jose's precedent, `MAX_JWE_HEADER_LENGTH` 8 KiB.
  Then: `exp`/`iat` must be NumericDates, and `bool` is excluded by hand because `exp: true` is
  an `int` in Python; the payload is parsed only *after* the signature verifies; `zip` and `crit`
  are refused rather than ignored, since a `zip` we skip past means handing the caller DEFLATE
  bytes as if they were plaintext; `apu`/`apv` must be strings; the IV and tag are length-checked
  before AESGCM sees them, so "malformed" stops reporting itself as "authentication failed".
- `b64u_decode` now rejects anything outside the base64url alphabet instead of silently
  discarding it. `base64.urlsafe_b64decode` drops stray characters, so a client that reached for
  standard base64 got `+` and `/` decoded as *something* — a plausible-looking key nobody can
  encrypt to. The tokenserver already matched base64url by hand for this reason.
- `alg=dir` is gone in both directions, not just `encrypt_jwe_dir` as planned. The plan's argument
  for deleting the encrypting half — referenced only by `tests/test_jwe.py`, nothing on the wire —
  is exactly as true of the decrypting half once no producer remains, and it left `decrypt_jwe`
  taking `bytes | EllipticCurvePrivateKey` for no caller. `decrypt_jwe` now takes a P-256 private
  key, and the union checks it needed went with it.
- The RS256 known-answer test the file lacked: RFC 7515 App. A.2, extracted from the RFC text
  rather than typed in. Both directions — `verify_jwt` accepts the RFC's token under the RFC's
  key, and `jwk_to_private_key` + PKCS#1 v1.5 reproduces the RFC's signature byte for byte, which
  is only possible because v1.5 is deterministic where PSS would leave verification as the only
  pinnable half. It also fails closed on `exp` without a `now`, since the vector expired in 2011.
- Negative tests: the full list above, plus a payload that is not an object, a header that is not
  an object, a signature that is not base64url, an `epk` that is missing or not an object, a
  non-empty encrypted-key segment, and IVs and tags of the wrong length.
- `tests/test_jose_properties.py` — hypothesis over the parsers. The named tests are a list of
  known failures; the property is the invariant behind the list, which a list cannot cover:
  whatever arrives at `verify_jwt` or `decrypt_jwe`, what comes back out is the claims, the
  plaintext, or `JWTError`/`JWEError` — never a `binascii.Error` or a `TypeError`, because the
  three callers turn those two into a 401 and anything else into a 500 with a traceback on an
  unauthenticated route. Plus round trips, the expiry boundary, and single-*byte* mutation of
  every segment (bytes, not characters: the trailing base64url character carries unused bits, so
  two spellings can decode to the same bytes and a character-level flip is allowed to be a no-op).
- Verified: 703 tests, `ruff check` and `ty check` clean.

### Phase 10 — security audit ✅ done

The code is complete and the dependency set is settled, so there is a fixed target to audit.
Two things make this worth doing properly rather than as a `bandit` run: the threat model is
unusual — an internet-facing sign-in endpoint guarding a household's entire browsing history,
operated by one person with no ops team — and this codebase departs from the reference in a dozen
deliberate places, each of which is a security decision no one but its author has reviewed.

**1. The divergences, first, because they are the unreviewed part.** Collect every "deliberate
divergence" from the phases above into one list — phase 12 documents the same list, so build it
here — and re-derive each argument rather than re-reading its original justification:

- accounts-API HAWK MACs parsed and discarded (`auth/credentials.py`, matching
  `hawk-fxa-token.js`). The conclusion that the tokenId *is* the credential is upstream's; confirm
  nothing in fxa-lite grants more on a HAWK header than on the equivalent Bearer one.
- `strictScopeValidation` on, unregistered scopes dropped (`oauth/grant.py`) — stricter than
  upstream; confirm a drop cannot become a grant on the refresh path.
- `aud` checked at the tokenserver — stricter; confirm `grant.py` is the only thing minting that
  audience.
- the storage HAWK payload hash **is** verified — stricter, and the most interesting item here:
  confirm the "client sent no hash" path is genuinely the specification's and not a bypass. An
  attacker who strips `hash=` from a captured signed request gets a body they can rewrite; work
  out exactly what the MAC still covers and whether that is enough.
- `tokenserver_shared_secret` derived from the OAuth signing key when unset — confirm the
  derivation is domain-separated from every other use of that key.
- the two upstream bugs deliberately not reproduced (`do_append`, wipe-vs-open-batch) — confirm
  not reproducing them cannot be driven the other way by a client that expects them.
- `upgradeNeeded: false`, `metricsEnabled: false`, `/v1/oauth/destroy` not revoking access tokens,
  `acr_values=AAL2` refused with errno 120.

**2. The out-of-scope list, repriced as security rather than as features.**

- **There is no rate limiting anywhere.** The customs server was dropped and nothing took its
  place. `POST /v1/account/login` runs scrypt at N=65536, r=8 — roughly 64 MB and ~100 ms of
  *server* work per unauthenticated request, on a machine that is also somebody's NAS. That is a
  denial-of-service amplifier before it is a password-guessing surface. Decide explicitly: a
  per-IP and per-email limiter in front of the scrypt call, or a proxy-level limit documented as
  *required* rather than suggested, or accepted with the reasoning written down. Do not leave it
  undecided, which is what it is today.
- No password reset means a forgotten password is unrecoverable **and** that there is no reset
  flow to attack. State both; only one of them is a cost.
- No 2FA means the password is the entire authenticator for `kB`. The CLI's 12-character minimum
  is the only control, and nothing rotates the key it protects.

**3. The mechanical sweep, where tooling reads better than a human.**

- `ruff`'s `S` ruleset (flake8-bandit) added to `select`, which is `["E","F","I","UP","B","SIM"]`
  today — so none of it has ever run. Expect noise around `assert` in tests; scope it per directory.
- SQL built with f-strings: `syncstorage/store.py:246`, `:387`, `:447` interpolate placeholder and
  column lists. That is legitimate and it is also exactly what a real injection looks like at a
  glance. Confirm every interpolated fragment derives from a literal and never from request data,
  and pin that with a test.
- `hmac.compare_digest` on every secret comparison — 9 call sites today. Audit for a `==` that
  should be one, especially password verify, token lookup and the HAWK MAC.
- Request limits: pydantic caps individual fields (`oauth/models.py`), but nothing caps a request
  body, a batch, a collection or the database, and uvicorn imposes no body limit by default. An
  unauthenticated 2 GB POST is currently a memory event.
- `/storage/{collection}/{id}`: ids reach a table rather than a filesystem, but confirm the
  validation and pin it.
- The four handlers in `app.py`, the bare `Exception` one included: confirm no path leaks a
  traceback, a SQL fragment or a filesystem path into any of the three envelopes.
- Secrets at rest: the signing key is written 0600 by `keygen` — confirm `serve` never widens it —
  plus the SQLite file mode, and what a database leak actually yields. Codes and refresh tokens
  are stored under `sha256`; confirm session and keyFetch rows store only the derived id.
- Dependency audit and lockfile pinning; a floor on `cryptography` that is not merely "whatever
  resolved".

**4. Deployment, which is where a household server actually gets breached.** TLS termination;
`identity.fxaccounts.allowHttp` never set outside a LAN test; `public_url` versus a rewriting
proxy — phase 6 already made HAWK read `public_url` rather than `Host`, so confirm nothing else
reads `Host`; the WebChannel origin allowlist; CSP and `Referrer-Policy` on every content route
rather than only on the shell. This ends as a "Deploying this safely" page, which is a phase 12
deliverable.

Run `/security-review` over the branch as one input, not as the audit: it reviews a diff, and the
findings that matter here are architectural and span all six tiers.

Deliverable: findings triaged fixed / accepted-with-reason / out-of-scope, with the accepted ones
written into the docs rather than into a file nobody opens. Every fix lands with a test, as
everything else in this project has. Then re-run the suite **and** phase 8 against real Firefox —
the audit will touch auth-path code, and that path has exactly one integration test that matters.

As built:

- **`AUDIT.md` is the deliverable**, written as a reading pass first and then annotated with what
  each finding became. Eight went to *fix*, eleven to *confirm and pin*, five to *accept*, one to
  *noted, not fixed*. The accepted five are in the README's new **Security** section — the file an
  operator actually opens — alongside what the deployment is required to provide.
- **The three cheapest findings were the ones no one had looked at.** `[log] level = "debug"`
  wrote a complete, spendable Sync credential to the terminal: `/token/1.0/sync/1.5` answers
  `{"id", "key"}` and neither name was in `SECRET_KEYS`. `key` could be redacted globally; `id`
  could not, because everywhere else it is a BSO id, a device id or a client id — so `tracing`
  grew `PATH_SECRET_KEYS`, one entry, scoped to `/token/`. The SQLite file was created with the
  umask, i.e. 0644, holding `kA` and the session token ids that *are* the credential; it is now
  chmod'd 0600 before `PRAGMA journal_mode = WAL`, which is what makes SQLite give `-wal` and
  `-shm` the same mode. And `/static/icon.svg` — same-origin SVG, which is a document when it is
  navigated to — was served with none of the headers the shell gets.
- **The two decisions the plan left open, decided.** Registration: `POST /v1/account/create` was
  wire-compatible and ungated, so anyone who could reach the origin could spend a 64 MiB scrypt
  and keep the account. It is off unless `[security] open_registration` says otherwise; no page in
  `content/assets/` calls it, so nothing real pays for that. Rate limiting: **failed** password
  checks are counted per account, before scrypt, and answered 429 / errno 114. Counting failures
  rather than requests is what makes it safe — an attacker cannot lock a household out of its own
  accounts — and `accounts.authenticate` still raises `unknown_account` before stretching, so an
  unknown address drives no scrypt and earns no table entry. Per-IP stays the proxy's job, since
  behind nginx every client is `127.0.0.1`; phase 11's `limit_req_zone` already ships uncommented.
- **A body cap was the one structural change.** Every tier reads the body before it checks the
  signature — it must, because the signature may cover the body — so "authenticate first" was
  never available. `middleware.BodyLimit` is pure ASGI under `tracing.Trace`: a declared
  `Content-Length` over the limit is refused without reading a byte, and a chunked body is counted
  as it arrives. It renders its own refusal in all three envelopes, because a middleware runs
  outside every handler in `app.py` and a Sync client handed the accounts envelope reads a JSON
  object where the protocol says an integer.
- **`ruff`'s `S` found nothing.** Ten findings in `src`, all of them the rule misreading a
  protocol constant (`"passwordChangeToken"` is a `tokenTypeID`, `"at+JWT"` is a JOSE header) or
  the four `store.py` queries, where every interpolated fragment is a literal — a run of `?`, a
  fixed column list, an `ORDER BY` reached by dict lookup. Each carries a `noqa` with the reason,
  and `S` is now in `select` so the next one has to be argued for.
- **The "confirm and pin" list is `tests/test_security.py`.** HAWK grants no more than Bearer; a
  dropped scope cannot be regranted on refresh; one file mints the tokenserver audience; a BSO id
  of `'or'1'='1` is data; `hmac.compare_digest` is in the five files it should be in; no envelope
  carries a traceback. The one thing a test cannot express — that the HAWK payload hash cannot be
  stripped, because `hash` is a field *inside* the normalized string — is written down in
  `AUDIT.md` instead.
- Verified: 813 tests, `ruff check` and `ty check` clean. **The phase-8 re-run against real
  Firefox is still owed** — this phase touched the auth path (`accounts.authenticate` grew the
  throttle, every request now passes a body cap), and that path has exactly one integration test
  that matters. Sign in, fetch keys, take a tokenserver token and sync a collection before this
  is called finished.

### Phase 11 — Docker ✅ done

`uvx fxa-lite --config fxa.toml` is the intended outcome, but the machine a household actually
runs this on is a NAS or a small always-on box that already hosts three other things, and there
the unit of deployment is a container, not a `uv tool install` into somebody's home directory.
The image should make the same promise as the CLI — one process, one file of state — and it
should be boring: no entrypoint script that generates secrets, no supervisor, no bundled proxy.

**Build.** Multi-stage, following the astral uv guidance: a builder on
`ghcr.io/astral-sh/uv:python3.13-trixie-slim` (or `python:3.13-slim-trixie` with the uv binary
copied in from a pinned distroless tag), and a runtime on plain `python:3.13-slim-trixie` that
receives `/app/.venv` and nothing else.

- `uv sync --locked --no-dev --no-editable`, split into two layers — dependencies from a bind
  mount of `pyproject.toml` + `uv.lock` first, the project after `COPY . /app` — so a source edit
  does not re-resolve `cryptography`. `--no-editable` is what makes the source-free runtime stage
  possible; `--no-dev` keeps `pytest`, `ruff` and `ty` out of a deployed image.
- `ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0`, plus a
  `--mount=type=cache,target=/root/.cache/uv`.
- Pin, in the spirit of `UPSTREAM.toml`: the uv image by `@sha256:` digest, not by `:latest`, and
  the base image likewise. `gh attestation verify --owner astral-sh oci://ghcr.io/astral-sh/uv:<v>`
  is one command and worth running once when the pin is chosen; record it beside the pin.
- `--locked` is also a free CI check: if `uv.lock` ever drifts from `pyproject.toml`, the image
  build fails rather than quietly resolving something else.

**`.dockerignore` comes first, before any of that, and it is the step with teeth.** `resources/`
is the two upstream checkouts and is 844 MB today — it is gitignored, so it is invisible to
review, and a missing `.dockerignore` sends every byte of it to the daemon as build context on
every build. The same file is what keeps deployment secrets out of an image that may be pushed to
a registry: `fxa.toml`, `*.sqlite*`, `signing-key.json`, `retired-key.json`, `.venv/`, `.git/`,
and the caches. Mirror `.gitignore`'s "local deployment state" block and add a test or a build
assertion that the built image contains none of those paths — "I checked once" is exactly the
kind of claim phase 12's CI exists to stop the project from making.

**State is one volume, and the config file already says so.** `config.py` resolves relative paths
against the directory holding the config, which was written so a config plus its database and
signing key move as a unit; a container is that unit. Mount one volume at `/data`, put `fxa.toml`
in it beside `fxa.sqlite` and `signing-key.json`, and set `FXA_LITE_CONFIG=/data/fxa.toml` — the
env var `cli.py:112` already honours. No new configuration surface, no flags in `CMD`, and
nothing in the image is writable that needs to be.

**Two container-shaped traps in the existing defaults:**

- `[listen] host` defaults to `127.0.0.1`, which inside a network namespace means unreachable —
  including by the healthcheck. The image sets `0.0.0.0` (via `CMD ["serve", "--host", "0.0.0.0"]`,
  which `cmd_serve` already accepts) and compose publishes `127.0.0.1:9000:9000` so the loopback
  binding moves to the host, where it belongs, in front of whatever proxy terminates TLS.
- `public_url` must be the external `https://` origin, never the container's. Phase 6 already made
  HAWK read `public_url` rather than `Host`, so a rewriting proxy is fine — this is a documentation
  point, but it is the first thing that goes wrong behind a reverse proxy and it deserves a line in
  `fxa.example.toml` rather than only in the docs.

**Bootstrap is interactive and stays that way.** `keygen` and `account add` are administrative acts
on the machine holding the database, and `account add` prompts through `getpass`:

```sh
docker compose run --rm fxa-lite keygen
docker compose run --rm -it fxa-lite account add you@example.com
docker compose up -d
```

which wants `ENTRYPOINT ["/app/.venv/bin/fxa-lite"]` and `CMD ["serve", "--host", "0.0.0.0"]` so
every subcommand is reachable without `--entrypoint`. **Do not** generate a signing key from an
entrypoint script when one is missing: a container that silently mints a new key after a volume
fails to mount looks like it recovered while having invalidated every outstanding token, and
`cmd_serve` already exits 1 with the right instruction. The failure that is loud on a laptop must
stay loud in a restart loop.

**Runtime user and file modes.** Run as a non-root uid — `USER` in the Dockerfile plus `/data`
created and chowned in the image, which is what makes a *named* volume inherit the right
ownership on first use; a *bind* mount does not, and needs a host-side `chown` that the deployment
page has to spell out with the uid in it. `keygen` writes the key 0600, which phase 10 confirms
`serve` never widens — that guarantee only holds if the file is owned by the user the container
runs as, so the smoke test should assert both the mode and the owner after a containerised
`keygen`.

**Compose, one service, hardened by default.** `read_only: true` with a `tmpfs: /tmp` (all state
is `/data`, so the root filesystem has no reason to be writable), `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, `restart: unless-stopped`, an explicit `user:`, and the
loopback port publication above.

**TLS, and a reversal.** This phase originally said no nginx, no Caddy and no certificate
machinery — TLS is the host's job, and bundling a proxy doubles the surface of a project whose
whole argument is that the reference deployment has too many moving parts. Phase 8 overruled the
premise: the sign-in page stretches the password with `crypto.subtle`, which browsers expose only
in a secure context, so **a phone cannot sign in over plain HTTP at all**. TLS is not the
deployment polish this phase took it for; it is the difference between a working household server
and a desktop-only toy. "The host's job" is a fine answer for somebody who already runs a proxy
and a dead end for the person this project is for.

So the middle: the *default* stack stays one service, and the proxy is opt-in.

- **`deploy/nginx.conf.example`** — a complete server block for one origin in front of
  `127.0.0.1:9000`, annotated the way `fxa.example.toml` is. It is the deliverable that unblocks
  phase 8's mobile half, and it may have to land ahead of the rest of this phase.
- **An `nginx` service in `docker-compose.yaml` behind `profiles: ["tls"]`**, so
  `docker compose up -d` is still one container and `docker compose --profile tls up -d` is the
  public deployment. It mounts the example config and the host's certificate directory read-only;
  it does **not** run certbot. Issuance stays one documented `certbot certonly` on the host plus a
  renewal hook that reloads the container — a compose file that mints certificates is exactly the
  entrypoint-generates-secrets pattern this phase refuses elsewhere. With the proxy up, the app
  service publishes nothing to the host at all; nginx reaches it over the compose network.

Five things the example config has to get right, each of which is a specific failure fxa-lite
would show as something else:

- **`client_max_body_size` at least 2625536 bytes** — `/info/configuration` advertises
  `max_request_bytes` = 2625536, and Firefox believes it. nginx's 1 MB default turns a history
  batch into a 413 that never reaches the app, and the client reads it as a stalled sync.
- **One `location /`, proxying to one upstream, with no path rewriting.** The discovery document
  and the tokenserver's `api_endpoint` are built from `public_url`, and HAWK signatures cover the
  URL the tokenserver handed out; a proxy that strips or adds a prefix breaks every signature at
  once. Whatever TLS terminates on must be the origin `public_url` names, exactly.
- **`proxy_set_header Host $host` and `X-Forwarded-Proto https` are courtesy, not load-bearing** —
  fxa-lite reads `public_url` and never the request's `Host` (phase 6, deliberately). Say so in
  the file, or the next person will spend an afternoon on headers that change nothing.
- **HSTS belongs here**, since the app does not set it and a secure context is now a hard
  requirement rather than a preference. So does the redirect from `:80`, with the ACME challenge
  location carved out ahead of it.
- **The rate limit phase 10 has to decide about.** `limit_req_zone` on `/v1/account/login`,
  `/v1/account/create` and `/v1/session/reauth` is the proxy-level half of that decision; if the
  audit lands on "documented as required rather than suggested", this file is where the
  requirement is met and it must ship uncommented.

`HEALTHCHECK` targets `/__heartbeat__`, which pings the database rather than merely answering —
`/__lbheartbeat__` cannot tell a broken volume from a healthy one. There is no `curl` in a slim
image and adding one for this is silly; use `python -c` with `urllib.request` against
`127.0.0.1:<port>`.

**Two operational facts that belong in the compose file's comments, not only in the docs:**
SQLite over NFS or SMB has broken locking, so `/data` must be a local filesystem or a named
volume backed by one — the "household NAS" that motivates this phase is also the machine most
likely to get this wrong; and backup is `docker compose stop` (or a `sqlite3 .backup`) over one
directory, which is the whole disaster-recovery story and reads as a selling point rather than a
caveat.

**Multi-arch, because that NAS is probably arm64.** `docker buildx build --platform
linux/amd64,linux/arm64`. `cryptography` publishes manylinux wheels for both, so the build stays a
download; the failure mode if a wheel is ever missing is uv falling back to an sdist that wants a
Rust toolchain and OpenSSL headers, turning a fifteen-second build into a broken one. If that
happens the fix is a pin, not a compiler in the builder stage. Glibc over musl for the same
reason — alpine would mean musl wheels or source builds for no benefit here.

**Development is deliberately not containerised.** `uv run fxa-lite serve --reload` is faster than
any bind-mount-and-watch arrangement, and `tests/js/*.mjs` need `node`, which has no business in a
deployment image. `docker compose watch` is documented in the uv guide and is the right tool for a
different project; note the decision so the question is not reopened.

**Deliverables:** `Dockerfile`, `docker-compose.yaml` (with the `tls` profile),
`deploy/nginx.conf.example`, `.dockerignore`, a `scripts/docker-smoke.sh`
that builds the image and drives keygen → `account add --password` → `up` → assert the discovery
document and `/__heartbeat__` → assert the secrets are absent from the image, and the
`fxa.example.toml` comment on `public_url` behind a proxy. Phase 12's CI builds the image on PR
(build only, no push) and phase 12's deployment page is where this stops being a list of flags and
becomes instructions.

**Shipped**, and where it went differently:

- `Dockerfile`: builder on `ghcr.io/astral-sh/uv:0.11.29-python3.13-trixie-slim`, runtime on
  `python:3.13-slim-trixie`, both pinned by the digest of their multi-arch OCI index so one pin
  still builds amd64 and arm64. `uv sync --locked --no-dev --no-editable` in two layers, cache
  mount, `UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0`. 173 MB, and `/app`
  contains `.venv` and nothing else. The `gh attestation verify` command is recorded beside the
  pin but was **not run**: the `gh` on this machine is 2.46, which predates the subcommand.
- **`.python-version` had to join `.dockerignore`**, which the phase did not anticipate. It says
  3.12 (the project supports >=3.12); copied into the build by `COPY . /app` it wins over the
  base image's interpreter and the second `uv sync` fails with "No interpreter found for Python
  3.12" — after the first one has already succeeded, which is what makes it confusing. The FROM
  line is the only place that choice should live. `tests/test_docker.py` pins the exclusion with
  the reason attached.
- `.dockerignore` mirrors `.gitignore`'s deployment-state block, with `**/` where a pattern has
  to match at any depth — a bare `*.sqlite` matches only the context root, which is exactly the
  kind of near-miss this file is bad at showing. Both halves are asserted: `tests/test_docker.py`
  reads the block out of `.gitignore` and requires each pattern in `.dockerignore` (so adding a
  secret to one and forgetting the other fails a test), and `scripts/docker-smoke.sh` proves it
  against the built image with a `find` over the layers.
- **The compose port publication is unconditional, and the phase asked for it to disappear under
  the `tls` profile.** Compose has no mechanism for that — `profiles` scopes services, not keys —
  and the alternatives all cost more than the property is worth: a second service definition, a
  `network_mode: service:` pairing that moves 80/443 onto the app service, or an env var whose
  "off" value compose rejects. It stays `127.0.0.1:9000:9000` with a comment saying that under
  the profile it is only useful for local debugging and can be commented out. Loopback-only
  publication next to a proxy on the same host is not a regression; the sentence in the plan was.
- `deploy/nginx.conf.example` has all five: `client_max_body_size 3m` (against the advertised
  2 625 536 — `tests/test_docker.py` compares it to `LIMITS.max_request_bytes` rather than to a
  transcribed number), one `location /` and no rewriting, the proxy headers marked as courtesy,
  HSTS with the `:80` redirect behind an ACME carve-out, and `limit_req_zone` uncommented per the
  audit's F3. Verified with `nginx -t` in the pinned nginx image, which the smoke script re-runs.
- **The upstream address is one edited line, not two files.** The example serves both a host nginx
  (`127.0.0.1:9000`) and the compose profile (`fxa-lite:9000`, over the compose network, since
  `127.0.0.1` in the proxy container is the proxy). Splitting the `upstream` block into a second
  mounted file was the alternative; it is worse, because the file has to be copied and edited
  anyway — `server_name` and two certificate paths — so the upstream is a fourth edit in a list
  of three, all marked `# EDIT`. `deploy/nginx.conf` is gitignored, as `fxa.toml` is.
- `scripts/docker-smoke.sh`: build → assert nothing secret, no source tree, no `uv` and no
  `pytest` in any layer → assert `serve` without a key still exits 1 with the right instruction →
  config, `keygen`, `account add --password`, `account list` → `serve` hardened exactly as compose
  hardens it → `/__heartbeat__`, the discovery document (asserted to name the external origin and
  *not* the container's), `/v1/jwks` → `compose config` and `nginx -t`. Passes end to end.
- The signing key after a containerised `keygen` is `600 fxa fxa` — mode *and* owner, since either
  half alone proves nothing. The database was `644 fxa` at the time: correct ownership, and the
  mode was AUDIT.md's F5, then still open, so the smoke script warned and named the finding.
  Phase 10 fixed F5 and the check is now an assertion.
- Not done, deliberately: no multi-arch build was executed. `docker buildx build --platform
  linux/amd64,linux/arm64` is recorded in the Dockerfile header, and both pinned indexes were
  checked to carry linux/arm64, but this machine runs podman without a buildx equivalent, and an
  emulated arm64 build proves less than phase 12's CI will.

### Phase 12 — documentation and CI ✅ done

Sphinx under `docs/`, published to GitHub Pages by `.github/workflows/`. There is no CI at all
today: "`ruff check` and `ty check` clean" at the end of every phase is a claim a human made six
times. So the first workflow to write is not the docs one.

**CI** (`.github/workflows/ci.yml`) — beyond what was asked; drop it if you want the docs alone.
`uv sync`, then `pytest`, `ruff check`, `ty check`, plus a build-only `docker buildx build` of
phase 11's image, on push and PR. The catch: the node-driven
content tests (`tests/js/*.mjs`) *skip* when `node` is absent, so the runner needs
`actions/setup-node` or they quietly do not run — and they are the only coverage of the
browser-side crypto, which is the coverage this project can least afford to lose silently. Assert
the collected count, or make them fail rather than skip when `CI` is set.

**Docs** (`docs/`, with `sphinx`, `myst-parser`, `furo` and `sphinxcontrib-mermaid` in a `docs`
dependency group — never a runtime dependency):

- *Running it.* The README's four commands are the quickstart and stay in the README; pull them in
  with a MyST `include` rather than copying, or the two drift within a month. The page around them
  is what the README deliberately is not: `fxa.example.toml` walked key by key, `keygen` and what
  a rotation costs, reverse proxy and TLS, the `about:config` prefs from phase 8, and backup —
  one SQLite file plus one key file, and what happens when you lose either. Both deployment shapes
  belong here: `uvx` on the host, and phase 11's container with its `/data` volume, its bind-mount
  ownership caveat and the `public_url`-behind-a-proxy rule. This is also where phase 10's
  operator-dependent findings land as instructions — TLS termination and the rate limit in front
  of the scrypt call are compose-level answers as much as they are code-level ones.
- *Pointing a browser at it.* Every client, in one table, derived from `public_url` and nothing
  else: the desktop `about:config` prefs, and — the half that is missing from every self-hosting
  write-up including this plan until now — Fenix's Sync Debug fields, with the secret-menu route to
  them and the origin-versus-full-URL asymmetry between the two called out, since that is where the
  attempt fails. Phase 8 established none of the four questions it set itself —
  the optional sync field, the sign-out requirement, the React page's paths, and iOS — because
  Android synced without any of them being settled, so **establishing them is work this phase
  inherits rather than prose it transcribes**. Three of them are one session with a phone; the
  fourth may end in "iOS cannot be pointed at a custom server", which is an answer worth printing. A short version of this table goes in the README
  as well — the question "what do I type into my phone" arrives before anyone opens the docs — so
  include it from one source rather than writing it twice.
- *Architecture.* The prefix table above, the six tiers and why they are one process, the schema
  and each table's lifetime, and the three error envelopes together with the reason there are
  three. A reader's first instinct is that this is sloppiness; the doc should say otherwise before
  they open the PR.
- *Message flow.* Mermaid sequence diagrams — the thing this project currently has no
  representation of anywhere. Three: the WebChannel handshake (`fxa_status` → `can_link_account` →
  `login` → `oauth_login`, with phase 4's two ordering rules marked *on the diagram*, since they
  are what a reimplementer gets wrong); sign-in from typed password through PBKDF2 to `kB`; and
  the sync flow from `kB` through scoped-key derivation, `keys_jwe`, the code exchange, the
  tokenserver and into a HAWK-signed storage request. That last one is
  `test_the_whole_stack_composes` drawn as a picture — keep the two side by side so neither can
  drift alone.
- *Provenance and divergences.* The chapter that justifies the project's existence. Phase 7's
  `UPSTREAM.toml` rendered as a table — which reference, which commit, which files, what we took —
  then the divergence list phase 10 assembled: what upstream does, what fxa-lite does, why, and
  what it costs. Source it from one place, not two: either mark each divergence in the code with a
  uniform `# DIVERGENCE:` comment and generate the table, or author the table and add a test
  asserting markers and rows agree. There are zero such markers today; the information lives in
  prose in this plan and in comments at the routes, which is exactly why phase 10 has to collect
  it before phase 12 can publish it.
  One caution, since this chapter is public: "here is where our auth server is deliberately unlike
  the reference" is a useful document for somebody attacking a running instance. Write the
  reasoning, not an exploitation path, and put the operator-dependent phase 10 items — rate
  limiting, TLS — in the deployment page as instructions rather than here as a list of what is
  missing.
- *Crypto API.* `autodoc` over `fxa_lite.crypto`, whose docstrings already carry the protocol
  constants and the traps. Nearly free, and it is the part of the code most likely to be read by
  someone porting this elsewhere.

**Pages** (`.github/workflows/docs.yml`): `actions/configure-pages`, `upload-pages-artifact`,
`deploy-pages`; `permissions: {pages: write, id-token: write}`; on push to `main`, build-only on
PR. Build with `sphinx-build -W`, so a broken cross-reference fails CI instead of shipping — and
this documentation is nothing but cross-references. Pages has to be enabled on `jaj42/fxa-lite`
with "GitHub Actions" as the source, a one-time manual step in the repository settings that no
workflow can do for you.

Last: once the docs carry the architecture and the flows, `plan.md` stops being the only place
they exist. Decide then whether the plan stays as a build log or is retired into the docs. Do not
do both by half.

As built:

- **CI first, as the phase said.** `.github/workflows/ci.yml` runs `uv sync --locked`, `pytest`,
  `ruff check`, `ty check` and a `sphinx-build -W` in one job, and builds the phase-11 image in
  another. `--locked` rather than `--frozen`, so a `uv.lock` that has drifted from
  `pyproject.toml` fails here instead of resolving differently in CI than on the machine that
  wrote the change. The image job is build-only: there is no registry, and what it catches is
  what `tests/test_docker.py` structurally cannot — a withdrawn base digest, a `uv sync` that no
  longer resolves inside the builder stage, a `COPY` of a path that moved.
- **The node question is answered by failing, not by counting.** `tests/nodejs.py` is one
  function: `shutil.which("node")`, then skip — unless `CI` is set, in which case `pytest.fail`
  with the reason and the remedy. Asserting a collected count was the alternative and it is
  worse: it goes stale every time a test is added, and it fails with a number rather than with
  "your runner has no JavaScript runtime and these are the only coverage of the browser crypto".
  Verified both directions with `node` off `PATH` — 19 errors with `CI=true`, 19 skips without.
- **The divergence chapter is generated, and that was the whole argument of the phase.** Twenty
  `# DIVERGENCE:` markers now sit at the code that diverges, each carrying four fields —
  `upstream`, `fxa-lite`, `why`, `cost`. `docs/_ext/divergence_scan.py` is a stdlib-only parser;
  `docs/_ext/divergences.py` is the Sphinx directive that renders them as cross-reference targets,
  so `running.md` and `architecture.md` link *into* the list rather than restating it. There is
  no authored copy. The plan offered "markers and generate" or "author and assert agreement", and
  the second is the one that rots: two texts, one test, and the test can only ever check that the
  slugs match, never that the prose still describes the code.
- **`tests/test_divergences.py` guards the failure mode generation introduces**, which is that a
  divergence now vanishes from the docs by having its comment deleted — exactly what a refactor
  does to a comment it does not understand. The phase-10 list is pinned by slug in *both*
  directions: a marker that disappears fails, and a marker added without being listed fails too,
  because the point of the list is that somebody decided each entry was worth publishing.
- **`UPSTREAM.toml` is rendered by reading it twice.** `tomllib` gives the data and throws the
  comments away, and the comments are most of the value — a path says a directory was opened,
  while "hawk-fxa-token.js: the auth scheme we match, MAC-discarding included" says what was
  found there. So `docs/_ext/upstream.py` scans the raw text a second time for the note above
  each path and matches the two halves up.
- **The README is the single source for the parts a reader meets first.** Four blocks are fenced
  with `<!-- include: … -->` — the quickstart, the docker bootstrap, the desktop prefs, the Fenix
  fields — and the docs pull them in with MyST `include`. The direction matters: GitHub renders
  no includes, so the README has to hold the literal text and the docs have to be the ones
  quoting it. `tests/test_docs.py` pins the markers, that each is quoted somewhere, that none has
  gone empty, and that every page is in the toctree.
- **Six pages.** *Running it* walks `fxa.example.toml` key by key and lands phase 10's
  operator-dependent findings as instructions — TLS at exactly `public_url`, the proxy's
  `limit_req_zone`, the key's mode — plus what a rotation costs and what each of the four
  possible losses costs. *Pointing a browser at it* is the client table derived from `public_url`
  and nothing else. *Architecture* is the prefix table, the six tiers, the schema table by table
  and the three envelopes with the reason there are three. *Message flows* is the three mermaid
  sequence diagrams, with phase 4's two ordering rules marked on the first one. *Provenance and
  divergences* is the two generated chapters. *The crypto core* is `autodoc` over
  `fxa_lite.crypto`.
- **`-W` earned its place immediately.** MyST resolves `[](page.md#anchor)` only against *heading*
  slugs, so the eleven links into the generated list were dead on the first build and said so.
  They are `{ref}` roles now, against targets the directive registers on each entry's rubric —
  which also means Sphinx supplies the divergence's own title as the link text.
- **The docs group is a default group**, not an optional one. Nothing under `src/` imports any of
  it and `uv build` ships none of it — there is a test for the first half — but `docs/_ext/` is
  first-party Python that `ruff` and `ty` read like any other file, and an extension excluded
  from both is an extension that breaks on the day nobody is watching. `ty` needed
  `extra-paths = ["docs/_ext"]` to see it at all.
- 909 tests (was 838), `ruff check` and `ty check` clean, `sphinx-build -W` clean.

**What this phase did not establish.** Phase 8's four questions were inherited here as work, and
three of them are still work: whether Fenix's *Custom Sync server* field is needed at all given
that discovery advertises `sync_tokenserver_base_url`, what the two fields do to an
already-signed-in profile, and whether *Use New React Mozilla Account page* opens a path outside
`content/__init__.py:PAGE_PATHS`. Each is one session with a handset and none of them is a
reading of the source. The fourth — whether a shipping Firefox for iOS can be pointed at a custom
server — is unknown and may end in "it cannot", which is the answer worth printing. `docs/clients.md`
records all four as open in the place a person would look for them, rather than guessing; that is
the honest state, not a substitute for the answer.

**The plan stays, as a build log.** The architecture, the flows and the divergences now live in
`docs/`, and this file should not be the second copy of any of them — it already links nowhere
and is written in the past tense of decisions rather than in the present tense of behaviour. What
it keeps being is the record of *why each phase was attempted in the order it was*, including the
four things that turned out to be wrong, which is not documentation and does not belong on a
published site. So: no retirement, no migration, and no new architecture prose here. A future
phase describes what it did; when that changes how the thing behaves, the change lands in `docs/`
in the same commit.

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
- `scripts/upstream-diff.sh` — not a pass/fail on the code, but the question the code cannot
  ask itself: has upstream changed one of the files a constant was read from? Run it before
  bumping a pin, and bump the pin only with the change or the note that answers its diff.
- Manual: Phase 8, then `about:sync-log` and the Sync panel in `about:preferences#sync`.
- CI runs the first four of these on every push and pull request
  (`.github/workflows/ci.yml`), together with `sphinx-build -W` and a build of the image.
  `tests/js/*.mjs` no longer skip silently there: `tests/nodejs.py` fails when `CI` is set and
  `node` is absent, because they are the only coverage of the browser-side crypto and a run that
  skipped them looks exactly like a run that did not.

## Deliberately out of scope

Email/SMTP entirely, password reset and recovery keys, TOTP/2FA/recovery codes/passkeys,
sign-in unblock and the customs/rate-limit server (phase 10 reprices that last one as a
denial-of-service question, not a feature), subscriptions and payments, push
notifications and Send Tab, QR pairing (the channelserver), device commands — which mobile polls
for, so the queue's absence is now stated in the protocol's own words, 403/errno 202, rather than
as a 404 — metrics/Glean/Sentry,
the admin panel, and BrowserID (`/certificate/sign` is gone from the reference too — note that
the `fxa-credentials` grant is *not* BrowserID, despite upstream naming its payload field
`assertion`; see phase 3).

Send Tab and pairing are the two most likely "actually I do want that" additions later; both are
additive and neither changes the schema decisions above.
