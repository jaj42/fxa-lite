# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: **one process, one
SQLite file, no external services** — wire-compatible enough that a stock
Firefox Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in
and syncs, and a Firefox for Android pointed at it through Sync Debug does too.

Mozilla Accounts is open source, but the reference monorepo is built to run a
service for hundreds of millions of users. Standing it up self-hosted means
MySQL, Redis under eight separate hostnames, Firestore, an SMTP relay, nginx, a
channelserver and a Node monorepo — plus `syncstorage-rs`, which itself speaks
only MySQL, Postgres or Spanner. This is the same thing for a household: six
tiers that upstream deploys separately, served from one origin by one process.

```{include} ../README.md
:start-after: <!-- include: quickstart -->
:end-before: <!-- end: quickstart -->
```

That is the whole quickstart. Everything below is the part the README
deliberately is not.

## Where to start

[Running it](running.md)
: The config file walked key by key, signing keys and what a rotation costs,
  TLS and reverse proxies, the container, and backup — one SQLite file plus one
  key file, and what happens when you lose either.

[Pointing a browser at it](clients.md)
: Every client, derived from `public_url` and nothing else: the desktop
  `about:config` prefs, Fenix's Sync Debug fields and the secret-menu route to
  them, and what is known about iOS.

[Architecture](architecture.md)
: Six tiers in one process, the prefix each is mounted at, the schema and each
  table's lifetime, and why there are three error envelopes rather than one.

[Message flows](flows.md)
: The WebChannel handshake, sign-in from a typed password through to `kB`, and
  the whole sync path from `kB` to a HAWK-signed storage request — as sequence
  diagrams.

[Provenance and divergences](provenance.md)
: Which reference, which commit, which files, what was taken — and then every
  place fxa-lite deliberately behaves unlike it, with the argument and the cost.

[The crypto core](crypto.md)
: `fxa_lite.crypto`, whose docstrings carry the protocol constants and the traps
  in them. The part of this codebase most likely to be read by someone porting
  it somewhere else.

## What this is not

Email and SMTP entirely; password reset and recovery keys; TOTP, 2FA, recovery
codes and passkeys; sign-in unblock and the customs server; subscriptions and
payments; push notifications and Send Tab; QR pairing; device commands;
metrics, Glean and Sentry; the admin panel; and BrowserID. Accounts are
provisioned from the command line on the machine holding the database, and a
forgotten password is unrecoverable.

Those absences are not all equal, and several of them are security decisions
rather than missing features. [Provenance and divergences](provenance.md) makes
the argument for each one that shows up on the wire; the README's **Security**
section is where an operator reads what is required of the deployment.

```{toctree}
:hidden:
:maxdepth: 2

running
clients
architecture
flows
provenance
crypto
```
