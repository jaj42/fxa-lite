# fxa-lite

A slim, self-hosted Mozilla Accounts + Sync stack in Python: one process, one
SQLite file, no external services — wire-compatible enough that a stock Firefox
Desktop pointed at it via `identity.fxaccounts.autoconfig.uri` signs in and syncs.

**Documentation: <https://jaj42.github.io/fxa-lite/>** — running it, pointing
each browser at it, the architecture, the message flows, and the list of every
place this deliberately behaves unlike the reference. See
[plan.md](plan.md) for the design and the phase breakdown.

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

Phase 10 — the security audit — is done: `AUDIT.md` is the findings list and
its triage, the fixes ship in the code, and what was accepted rather than fixed
is written up under **Security** below.

Phase 11 shipped the container deliverables — `Dockerfile`, `docker-compose.yaml`
with an opt-in `tls` profile, `deploy/nginx.conf.example` and a smoke script that
drives the whole bootstrap against a built image.

Phase 12 shipped CI and the documentation: `.github/workflows/ci.yml` runs
`pytest`, `ruff check`, `ty check`, a `sphinx-build -W` and a build of the image
on every push and pull request — so "clean at the end of the phase" is a
recorded fact rather than a claim — and `docs/` is a Sphinx site published to
GitHub Pages. Two of its chapters are generated rather than written: the
provenance list from `UPSTREAM.toml`, and the divergence list from
`# DIVERGENCE:` markers at the code that does the diverging.

Phase 8 is done: **Firefox Desktop and Firefox for Android both sign in and sync
against it for real** — tokenserver, `meta/global`, `crypto/keys`, and uploads of
clients, prefs, tabs, bookmarks, addons and history. Everything in *Pointing a
browser at it* below is what has been seen to work rather than what the code
implies. Where a reading is all there is, it says so: on Android the *Custom
Sync server* field turns out not to be required — the client falls back to the
`sync_tokenserver_base_url` this server advertises and appends `/1.0/sync/1.5`
to it itself — but the instruction keeps the field, because that is the value a
phone has actually synced with. A phone needs TLS before any of it, because the
sign-in page needs a secure context (see below). Firefox for iOS remains
untested, and unlike the Android questions it is not one the source can settle.

## Usage

<!-- include: quickstart -->
```sh
cp fxa.example.toml fxa.toml            # edit public_url to taste
uv run fxa-lite keygen                  # writes paths.signing_key (RSA-2048, RS256)
uv run fxa-lite account add you@example.com
uv run fxa-lite serve
```
<!-- end: quickstart -->

There is no signup page and there will not be one: accounts are provisioned
from the command line on the machine holding the database.

```sh
uv run fxa-lite account list
uv run fxa-lite account remove you@example.com
```

## Docker

The machine a household runs this on is usually a NAS or a small always-on box,
where the unit of deployment is a container. The image makes the same promise as
the CLI — one process, one file of state:

<!-- include: docker-quickstart -->
```sh
docker compose run --rm --interactive fxa-lite \
    sh -c 'cat > /data/fxa.toml' < fxa.example.toml   # edit public_url first
docker compose run --rm fxa-lite keygen
docker compose run --rm -it fxa-lite account add you@example.com
docker compose up -d
```
<!-- end: docker-quickstart -->

Everything lives in one volume mounted at `/data`: `fxa.toml`, `fxa.sqlite` and
`signing-key.json`, found through `FXA_LITE_CONFIG=/data/fxa.toml` because
relative paths in the config resolve against the directory holding it. Backup is
a copy of that one directory, and there is nothing else to back up.

Two things to get right:

* **`public_url` is the external `https://` origin**, not the container's. The
  container binds `0.0.0.0` — inside a network namespace `127.0.0.1` is
  unreachable even by the healthcheck — and compose publishes `127.0.0.1:9000`
  on the host, in front of whatever terminates TLS.
* **`/data` must be a local filesystem.** SQLite over NFS or SMB has broken
  locking, which is the one way to lose data here. A named volume on the box's
  own disk is the safe default; a bind mount works too and has to be chowned to
  uid 1000, the uid the container runs as.

There is no entrypoint script, and it will not generate a signing key when one
is missing: a container that silently mints a key after a volume failed to mount
looks like it recovered while having invalidated every outstanding token. It
exits 1 and tells you to run `keygen`, in a restart loop as on a laptop.

`docker compose --profile tls up -d` additionally starts an nginx in front,
configured by `deploy/nginx.conf.example` — copy it to `deploy/nginx.conf` and
edit the four marked places. Certificates stay the host's job (`certbot certonly`
plus a renewal hook that reloads the container); nothing here issues them. If you
already run a proxy, use the example config with it directly and ignore the
profile.

`scripts/docker-smoke.sh` builds the image and drives the whole bootstrap
against a throwaway volume, including the assertions that no deployment secret
is in a layer and that `keygen` inside the container writes the key 0600 and
owns it.

Development is deliberately not containerised: `uv run fxa-lite serve --reload`
is faster than any bind-mount-and-watch arrangement, and the JavaScript tests
need `node`, which has no business in a deployment image.

## Pointing a browser at it

Everything is served from one origin, so `public_url` is the only value you
need. Below it is `https://fxa.example.com`.

**Firefox Desktop** — a fresh profile, `about:config`:

<!-- include: desktop-prefs -->
| Pref | Value |
|---|---|
| `identity.fxaccounts.autoconfig.uri` | `https://fxa.example.com` |
| `webchannel.allowObject.urlWhitelist` | `https://fxa.example.com` (origin, no trailing slash) |
| `identity.fxaccounts.allowHttp` | `true` — only when serving plain HTTP |
<!-- end: desktop-prefs -->

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

<!-- include: android-fields -->
| Field | Value |
|---|---|
| Custom Mozilla account server | `https://fxa.example.com` |
| Custom Sync server | `https://fxa.example.com/token/1.0/sync/1.5` |
<!-- end: android-fields -->

(Older builds call the first one *Custom Firefox Account server*.) The two are
not the same shape, which is the thing that catches people out: the account
field is an **origin**, and the app reads the same discovery document from it
that desktop does, while the sync field is a **full tokenserver URL** with the
`/1.0/sync/1.5` on the end. Leave *Custom Push server* empty — push
notifications are out of scope — and set the fields before signing in: an
account that is already connected keeps the server it connected to, and
changing either field asks the app to quit so the new values are read.
Discovery already advertises `sync_tokenserver_base_url`, so the second field
may well be redundant; that has not been tested, and setting it costs nothing.

Firefox for iOS is registered as an OAuth client, but whether a shipping build
can be pointed at a custom server is untested; assume for now that it cannot.

## Security

The threat model is unusual and worth stating: an internet-facing sign-in
endpoint guarding a household's entire browsing history, run by one person with
no ops team. Phase 10 audited the whole stack against it; `AUDIT.md` is the
findings list. What follows is what an operator has to know — the controls that
are on, and the risks that were accepted rather than fixed.

**On by default**

* **Registration is closed.** `POST /v1/account/create` answers 403 unless
  `[security] open_registration` says otherwise. Accounts come from
  `fxa-lite account add`.
* **Failed password checks are throttled per account** — ten inside five
  minutes, then 429 — so a guesser cannot keep paying the server 64 MiB of
  scrypt per attempt. Only failures count and a correct password clears the
  tally, so nobody can lock you out of your own account by guessing at it.
* **Request bodies are capped before they are read**: 64 KiB, and Sync
  storage's advertised `max_request_bytes` below `/storage`.
* **The database is created mode 0600**, and narrowed if it is found wider. It
  holds `kA` in the clear and session token ids that *are* the credential a
  client presents; treat a copy of it as a copy of the accounts. `kB` is not in
  there — that still needs the password.
* Every response carries `nosniff` and a content security policy; the sign-in
  page and its assets carry a full one.

**Required of the deployment**

* **TLS, terminated at exactly `public_url`.** The sign-in page derives the
  password with `crypto.subtle`, which browsers withhold outside a secure
  context, and `identity.fxaccounts.allowHttp` belongs on a LAN test and
  nowhere else. Nothing here reads the `Host` header — every URL and every HAWK
  signature base comes from `public_url` — so a proxy that rewrites `Host` is
  harmless and one that adds or strips a path prefix breaks every signature at
  once. See `deploy/nginx.conf.example`.
* **Per-IP rate limiting at the proxy.** Behind a proxy every client looks like
  `127.0.0.1`, so this is the only tier that can do it; the example config ships
  a `limit_req_zone` over the three password endpoints, uncommented.
* **Keep the signing key mode 0600.** `fxa-lite keygen` writes it that way;
  `serve` warns if it is found readable by anyone else.

**Accepted, with the reasoning**

* **A copy of the database is a set of live sessions.** The stored session
  token id is what a client presents — upstream's design, and why codes and
  refresh tokens are stored under `sha256` while these are not. Losing the file
  means revoking sessions, not that anyone can read Sync data: that needs `kB`,
  which needs the password.
* **Account existence is discoverable.** `POST /v1/account/status` says so
  outright, as upstream does, and an unknown address skips scrypt, so the
  timing says it too. The throttle does not close this and is not meant to.
* **There is no quota.** `max_total_bytes` is advertised and not enforced, so a
  signed-in account can fill the disk. Watch the disk, as you would anyway.
* **A forgotten password is unrecoverable.** There is no reset flow — which
  also means there is no reset flow to attack. Keep the password somewhere.
* **The password is the whole authenticator for `kB`.** No second factor, and
  nothing rotates the key it protects; the CLI's 12-character minimum is the
  only control. Use a passphrase.

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
drives the whole flow against a real server. Both skip if `node` is missing —
except when `CI` is set, where they fail instead. They are the only coverage of
the browser-side crypto, and a green run that skipped them looks exactly like a
green run that did not.

The documentation builds with:

```sh
uv run sphinx-build -W -b html docs docs/_build/html
```

`-W` because two of its chapters are generated from the tree — a
`# DIVERGENCE:` marker that has lost a field, or a path in `UPSTREAM.toml` that
upstream has renamed, should fail the build rather than publish a gap.
