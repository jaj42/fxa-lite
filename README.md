# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: one process, one
SQLite file, no external services — wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

See [plan.md](plan.md) for the design and the phase breakdown.

## Status

Phase 0 (scaffolding) — config loading and signing-key generation.

## Usage

```sh
cp fxa.example.toml fxa.toml    # edit public_url to taste
uv run fxa-lite keygen          # writes paths.signing_key (RSA-2048, RS256)
```

## Development

```sh
uv run pytest
uv run ruff check
uv run ty check
```
