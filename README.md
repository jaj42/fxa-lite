# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: one process, one
SQLite file, no external services — wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

See [plan.md](plan.md) for the design and the phase breakdown.

## Status

Phases 0–7 done: config and signing keys, the crypto core pinned to the
reference test vectors, the accounts API — sign-in, key fetch, sessions and
devices — the OAuth tier (authorization codes with PKCE, JWT access tokens,
refresh tokens, scoped-key metadata), the profile server, the two
`.well-known` discovery documents, the sign-in page (static HTML and vanilla JS
that stretches the password in the browser and speaks the Firefox WebChannel),
the Sync tokenserver, and Sync 1.5 storage — collections, records, batch
uploads and conditional requests, behind fully verified HAWK signatures — and
`UPSTREAM.toml`, which records the reference commits every protocol constant
here was read against.

Phase 8 is under way, and Firefox Desktop now signs in and syncs against it for
real: tokenserver, `meta/global`, `crypto/keys`, and uploads of clients, prefs,
tabs, bookmarks, addons and history. The desktop settings below are what has
been seen to work, not what the code implies. The Android settings are still
the latter — no phone has synced yet — and they need TLS first, because the
sign-in page needs a secure context (see below).

## Usage

```sh
cp fxa.example.toml fxa.toml            # edit public_url to taste
uv run fxa-lite keygen                  # writes paths.signing_key (RSA-2048, RS256)
uv run fxa-lite account add you@example.com
uv run fxa-lite serve
```

There is no signup page and there will not be one: accounts are provisioned
from the command line on the machine holding the database.

```sh
uv run fxa-lite account list
uv run fxa-lite account remove you@example.com
```

## Pointing a browser at it

Everything is served from one origin, so `public_url` is the only value you
need. Below it is `https://fxa.example.com`.

**Firefox Desktop** — a fresh profile, `about:config`:

| Pref | Value |
|---|---|
| `identity.fxaccounts.autoconfig.uri` | `https://fxa.example.com` |
| `webchannel.allowObject.urlWhitelist` | `https://fxa.example.com` (origin, no trailing slash) |
| `identity.fxaccounts.allowHttp` | `true` — only when serving plain HTTP |

The first pref is enough on its own: Firefox reads
`/.well-known/fxa-client-configuration` from that origin and finds the accounts,
OAuth, profile and tokenserver endpoints in it.

Two things that will otherwise cost you an evening:

* **Plain HTTP works on `localhost` and nowhere else.** The sign-in page derives
  your password with `crypto.subtle`, which browsers expose only in a *secure
  context* — `http://localhost` and `http://127.0.0.1` qualify, a LAN address
  like `http://192.168.1.10:9000` does not, and the page fails with
  `crypto.subtle is undefined`. Serving anything other than loopback means real
  TLS in front of fxa-lite.
* **Turn HTTPS-Only mode off for that origin**, or Firefox upgrades the request
  before it leaves the browser and the server sees a TLS handshake on a
  plaintext socket. The symptom is `Invalid HTTP request received` from uvicorn
  with no access-log line at all, which looks like a protocol bug and is not
  one. Loopback is exempt from the upgrade; a LAN address is not.

**Firefox for Android** — Settings → About Firefox → tap the logo five times to
unlock the secret menu, then Settings → **Sync Debug**:

| Field | Value |
|---|---|
| Custom Mozilla account server | `https://fxa.example.com` |
| Custom Sync server | `https://fxa.example.com/token/1.0/sync/1.5` |

(Older builds call the first one *Custom Firefox Account server*.) The two are
not the same shape, which is the thing that catches people out: the account
field is an **origin**, and the app reads the same discovery document from it
that desktop does, while the sync field is a **full tokenserver URL** with the
`/1.0/sync/1.5` on the end. Leave *Custom Push server* empty — push
notifications are out of scope — and set both fields before signing in.

Firefox for iOS is registered as an OAuth client, but whether a shipping build
can be pointed at a custom server is untested; assume for now that it cannot.

## Debugging a client

When a browser will not sign in or will not sync, the useful question is which
field of which request it disliked, and an access log cannot answer it. Run the
server at debug level:

```sh
uv run fxa-lite serve --log-level debug     # or [log] level = "debug" in fxa.toml
```

Every request and response is then written out with its body:

```
DEBUG    POST /v1/oauth/token -> 400 auth=none
    request : {"client_id": "5882386c6d801776", "grant_type": "fxa-credentials", "scope": "profile"}
    response: {"code": 400, "errno": 121, "error": "Bad Request", "message": "Invalid grant_type"}
```

Credentials are redacted to a prefix and a length before anything is written —
`authPW`, session and key-fetch tokens, access and refresh tokens, `keys_jwe`,
Sync payloads — so a trace can be read and pasted without handing over an
account. The prefix is there so two lines can be matched against each other.
The output still records who signed in and when, so treat it as sensitive.

On the browser side, the matching switches are `identity.fxaccounts.loglevel`
and `identity.fxaccounts.log.appender.dump`, both set to `Debug`, read in the
Browser Console (Ctrl+Shift+J). Sync's own logs are at `about:sync-log`.

## Development

```sh
uv run pytest
uv run ruff check
uv run ty check
```

The sign-in page's JavaScript is exercised under `node`, which is the only way
to reach it: `tests/test_content_crypto.py` runs it against the same
known-answer vectors as the Python crypto, and `tests/test_content_flow.py`
drives the whole flow against a real server. Both skip if `node` is missing.
