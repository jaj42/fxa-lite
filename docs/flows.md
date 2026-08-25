# Message flows

Three sequences. The first is the one a reimplementer gets wrong, the second is
where the password becomes a key, and the third is the round trip the whole
project exists for.

## The WebChannel handshake

Firefox opens `<public_url>/` in a tab and talks to the page over a
`CustomEvent` channel rather than over HTTP. The envelope is
`CustomEvent('WebChannelMessageToChrome', {detail})` where `detail` is
`JSON.stringify({id: 'account_updates', message: {command, data, messageId}})` —
a **string**, for Desktop. Replies arrive on `WebChannelMessageToContent`.

```{mermaid}
sequenceDiagram
    autonumber
    participant B as Firefox (chrome)
    participant P as sign-in page
    participant S as fxa-lite

    P->>B: fxaccounts:fxa_status<br/>{service, isPairing, context}
    B-->>P: {capabilities:{engines}, clientId?, signedInUser?}
    Note over P: the page offers back exactly the<br/>engines it was named, and declines none

    P->>P: email + password typed
    P->>B: fxaccounts:can_link_account {email, uid?}
    B-->>P: {ok}

    P->>S: POST /v1/account/login?keys=true
    S-->>P: {uid, sessionToken, keyFetchToken, authAt}
    P->>S: GET /v1/account/keys (Hawk, keyFetchToken)
    S-->>P: {bundle}  — single use, the row is deleted

    rect rgba(128,128,128,0.12)
        Note over P,B: RULE 1 — login must precede oauth_login
        P->>B: fxaccounts:login<br/>{email, uid, sessionToken, verified,<br/>verifiedCanLinkAccount, services.sync}
        Note over P,B: RULE 2 — on an OAuth flow this message carries<br/>NO keyFetchToken and NO unwrapBKey<br/>(they cause intermittent sync disconnects)
        B-->>P: (ack)
    end

    P->>S: POST /v1/account/scoped-key-data
    S-->>P: {scope: {identifier, keyRotationSecret, keyRotationTimestamp}}
    P->>P: derive scoped keys from kB, seal keys_jwe to keys_jwk
    P->>S: POST /v1/oauth/authorization<br/>{client_id, state, code_challenge, keys_jwe}
    S-->>P: {code, state, redirect}

    P->>B: fxaccounts:oauth_login<br/>{action, code, redirect, state, scope,<br/>offeredSyncEngines, declinedSyncEngines}
    B->>S: POST /v1/oauth/token {code, code_verifier}
    S-->>B: {access_token, refresh_token, keys_jwe}
```

The two rules marked on the diagram are the ones that cost days if missed, and
neither is visible from the server: nothing here would notice `oauth_login`
arriving first, or key material riding along on the `login` message.
`tests/js/signin_harness.mjs` drives the page's own JavaScript against a real
server and pins both, along with their mirror image on `fx_desktop_v3`, where
the key material **is** expected.

`redirect` is always the sentinel
`urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel`; nothing is ever navigated
to.

## Sign-in: from a typed password to `kB`

The password never leaves the browser, and neither does `kB`. What the server
stores cannot produce either one.

```{mermaid}
sequenceDiagram
    autonumber
    participant U as person
    participant P as page (crypto.js)
    participant S as fxa-lite
    participant D as fxa.sqlite

    U->>P: email, password
    Note over P: quickStretchedPW = PBKDF2-HMAC-SHA256(<br/>password, "…/quickStretch:" + email,<br/>1000, dkLen=32)
    Note over P: authPW     = HKDF(qsPW, info=".../authPW")<br/>unwrapBKey = HKDF(qsPW, info=".../unwrapBkey")

    P->>S: POST /v1/account/login?keys=true {email, authPW}
    S->>D: SELECT … WHERE normalized_email = ?
    Note over S: throttle checked here — after the lookup,<br/>before scrypt, so an unknown address<br/>never drives a 64 MiB hash
    Note over S: stretched = scrypt(authPW, authSalt,<br/>N=65536, r=8, p=1) → HEX STRING<br/>verifyHash = HKDF(UTF8(hex), ".../verifyHash")
    S->>S: compare_digest(verifyHash, stored)
    S-->>P: {uid, sessionToken, keyFetchToken}

    P->>S: GET /v1/account/keys (Hawk id = keyFetchToken id)
    S->>D: SELECT key_bundle; DELETE the row
    S-->>P: {bundle}  — hex(ciphertext ‖ mac), 192 chars

    Note over P: km = HKDF(bundleKey, ".../account/keys", 96)<br/>verify HMAC, XOR out (kA ‖ wrapKb)
    Note over P: kB = wrapKb XOR unwrapBKey
    Note over P,S: the server has kA and wrapWrapKb.<br/>It cannot compute kB without the password.
```

`wrapWrapKb` is what is actually stored: `wrapKb XOR HKDF(UTF8(stretched_hex),
".../wrapwrapKey")`. The IKM there really is the **hex string's ASCII bytes**,
not the 32 raw bytes, because the Node `hkdf` package does
`Buffer.from(string)`. Reproduce it literally or nothing interoperates — that
trap and its neighbours are in the [crypto API](crypto.md) docstrings.

## Sync: from `kB` to a stored record

This is `test_the_whole_stack_composes` drawn as a picture. Keep the two side by
side: if the diagram and the test disagree, one of them is wrong, and the test
is the one that runs.

```{mermaid}
sequenceDiagram
    autonumber
    participant C as client
    participant O as OAuth (/v1)
    participant T as tokenserver (/token)
    participant S as storage (/storage)

    Note over C: from kB —<br/>km  = HKDF(salt=b"", ikm=kB,<br/>      info=".../oldsync", L=64)<br/>k   = b64url(km)<br/>kid = keysChangedAt + "-" +<br/>      b64url(sha256(kB)[0:16])

    C->>O: POST /v1/oauth/token<br/>{code, code_verifier} or {grant_type: fxa-credentials}
    Note over O: access token is RS256, typ "at+JWT".<br/>Because the scope contains apps/oldsync,<br/>`aud` is the TOKENSERVER URL, not client_id.
    O-->>C: {access_token, refresh_token, keys_jwe}
    C->>C: decrypt keys_jwe (ECDH-ES + A256GCM) → the oldsync key

    C->>T: GET /token/1.0/sync/1.5<br/>Authorization: Bearer <access token><br/>X-KeyID: <kid>
    Note over T: verify RS256 locally, require apps/oldsync,<br/>require aud == this tokenserver,<br/>derive fxa_kid from the client state
    Note over T: allocate or look up the small integer uid.<br/>A changed client state RETIRES the old row<br/>and mints a new uid.
    Note over T: token   = b64url(payload ‖ HMAC(hmac_key, payload))<br/>derived = b64url(HKDF(secret, salt,<br/>          ".../derive/" + token))
    T-->>C: {id: token, key: derived, uid,<br/>api_endpoint: "<node>/1.5/<uid>", duration}

    C->>S: PUT /storage/1.5/<uid>/storage/bookmarks/record<br/>Authorization: Hawk id="<token>", ts, nonce, mac, hash
    Note over S: parse the tokenlib token, check the HMAC,<br/>re-derive the same MAC key, verify the MAC over<br/>ts ‖ nonce ‖ METHOD ‖ path?query ‖ host ‖ port ‖ hash ‖ ext
    Note over S: host and port come from public_url,<br/>never from the Host header
    S-->>C: 200, X-Last-Modified

    C->>S: GET /storage/1.5/<uid>/storage/bookmarks/record
    S-->>C: {id, modified, payload, sortindex}
```

Three things worth reading off this diagram:

**The audience swap is not a detail.** An access token whose scope contains
`https://identity.mozilla.com/apps/oldsync` is minted with `aud` set to the
tokenserver URL rather than to the client id. `oauth/grant.py` is the only place
that does it, which is what lets the tokenserver check `aud` at all where
upstream cannot ({ref}`marker <divergence-tokenserver-audience-checked>`).

**A key rotation is a new uid, not an updated row.** The client state — the
first 16 bytes of `sha256(kB)`, hex — is what the tokenserver keys on. Change
`kB` and the client gets a *different* small integer uid, so records encrypted
under the old key stay attached to the old one where nothing will try to decrypt
them with the new.

**The storage MAC is the only place fxa-lite verifies a HAWK signature.** The
accounts API parses `Hawk` headers and discards the MAC, as the reference does.
Here the MAC *is* the authorization: there is no session to look up, and the
token id travels in the clear in every request.
