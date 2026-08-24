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

What remains is phase 8: pointing a real Firefox — and a real phone — at it,
so the settings below are what the code says they should be rather than what
has been seen to work.

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
| `identity.fxaccounts.allowHttp` | `true` — only when serving plain HTTP on a LAN |

The first pref is enough on its own: Firefox reads
`/.well-known/fxa-client-configuration` from that origin and finds the accounts,
OAuth, profile and tokenserver endpoints in it.

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
