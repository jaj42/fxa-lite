# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: one process, one
SQLite file, no external services — wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

See [plan.md](plan.md) for the design and the phase breakdown.

## Status

Phases 0–6 done: config and signing keys, the crypto core pinned to the
reference test vectors, the accounts API — sign-in, key fetch, sessions and
devices — the OAuth tier (authorization codes with PKCE, JWT access tokens,
refresh tokens, scoped-key metadata), the profile server, the two
`.well-known` discovery documents, the sign-in page (static HTML and vanilla JS
that stretches the password in the browser and speaks the Firefox WebChannel),
the Sync tokenserver, and Sync 1.5 storage — collections, records, batch
uploads and conditional requests, behind fully verified HAWK signatures.

What remains is phase 7: pointing a real Firefox at it.

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
