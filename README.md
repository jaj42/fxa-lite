# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: one process, one
SQLite file, no external services — wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

See [plan.md](plan.md) for the design and the phase breakdown.

## Status

Phases 0–2 done: config and signing keys, the crypto core pinned to the
reference test vectors, and the accounts API — sign-in, key fetch, sessions and
devices. OAuth, the sign-in page and Sync itself are still ahead.

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
