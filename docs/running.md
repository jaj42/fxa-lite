# Running it

Two shapes, one set of state. On a host with `uv`:

```{include} ../README.md
:start-after: <!-- include: quickstart -->
:end-before: <!-- end: quickstart -->
```

In a container:

```{include} ../README.md
:start-after: <!-- include: docker-quickstart -->
:end-before: <!-- end: docker-quickstart -->
```

Everything else on this page is detail behind those eight lines.

## The config file

One TOML file; `fxa.example.toml` is the annotated copy to start from. Every
relative path in it resolves **against the directory holding it**, so a config,
its database and its signing key move as a unit — which is what makes the
container's `/data` volume work and what makes backup a directory copy.

`fxa-lite` finds it at `./fxa.toml`, or wherever `--config` says, or wherever
`FXA_LITE_CONFIG` says. Every subcommand takes `--config`.

### `public_url`

```toml
public_url = "https://fxa.example.com"
```

The single most important value in the file, and the one thing a bad deployment
usually gets wrong. It is the **external origin a browser types**, never the
address the process binds.

Nothing here reads the `Host` header. The discovery document, every OAuth
redirect, the tokenserver's `api_endpoint`, and the host and port inside every
Sync HAWK signature base are all built from this string. Two consequences,
both load-bearing:

* a reverse proxy that rewrites `Host` is **harmless**, which is unusual and
  deliberate;
* a proxy that adds or strips a path prefix breaks **every HAWK signature at
  once**, because the client signed the URL the tokenserver told it to use.
  Serve fxa-lite at the root of its own name.

Change `public_url` on a running deployment and outstanding access tokens stop
being spendable at the tokenserver — it checks `aud` (see
{ref}`the marker <divergence-tokenserver-audience-checked>`).
That costs clients one round trip, not a re-sign-in.

### `[listen]`

```toml
[listen]
host = "127.0.0.1"
port = 9000
```

Where the process binds, which is a different question from `public_url`.
Loopback is the right answer on a host with a proxy in front. The container
image binds `0.0.0.0` instead, because inside a network namespace `127.0.0.1`
is unreachable even by the healthcheck, and compose publishes it back onto the
host's loopback.

### `[paths]`

```toml
[paths]
database = "fxa.sqlite"
signing_key = "signing-key.json"
# retired_key = "retired-key.json"
```

Two files, and they are the entire state of the system. `retired_key` is the
**public** JWK of a key you have rotated away from; see below.

The database is created mode 0600 and narrowed if it is found wider, because it
holds `kA` in the clear and holds session token ids that *are* the credential a
client presents. `kB` is not in there — that still needs the password.

`/data` (or wherever the database lives) **must be a local filesystem**. SQLite
over NFS or SMB has broken locking, and that is the one way to lose data here.

### `[log]`

```toml
[log]
# level = "debug"
```

`info` by default. At `debug`, every request and response is written out with
its body, which is the only practical way to find out which field of which
request a browser disliked. Credentials are redacted to a prefix and a length
before anything is written — the prefix is there so two lines can be matched
against each other — but the output still records who signed in and when. Treat
a trace as sensitive; see the README's **Debugging a client**.

### `[security]`

```toml
[security]
# open_registration = false
# failed_login_limit = 10
# failed_login_window = 300
```

`open_registration` decides whether `POST /v1/account/create` provisions an
account for anyone who asks. It is **off**, and it should stay off: each attempt
is one unauthenticated scrypt — 64 MiB and about 100 ms of a household NAS —
with an attacker-chosen address and an account at the end of it. No page served
here calls that route; accounts come from `fxa-lite account add`. Turn it on
only to run the reference client's own signup flow, and turn it off after.

The other two are what is left of upstream's customs server: ten **failed**
password checks per account inside five minutes, then 429. Counting failures
rather than requests is what makes it safe to ship on by default — a correct
password clears the tally, so nobody can lock you out of your own account by
guessing at it. `failed_login_limit = 0` switches it off.

It does not limit by IP, and it cannot: behind a proxy every client is
`127.0.0.1`. That half is the proxy's job, and it is not optional — see
[TLS and the proxy](#tls-and-the-proxy).

### `[ttl]`

```toml
[ttl]
access_token = 21600
authorization_code = 900
tokenserver_token = 3600
```

Seconds. `access_token` stays at or below six hours on purpose: that is what
lets an access token be a self-contained JWT with no server-side row, and it is
the reason revoking one is a no-op (see
{ref}`the marker <divergence-access-tokens-not-revocable>`).
Raising it past six hours means an access token nobody can take away for longer
than that; lowering it costs clients more refreshes and nothing else.

### `[[clients]]`

Firefox Desktop, Fenix and Firefox for iOS are registered automatically with
the ids, scopes and redirect URIs the reference server gives them, so most
deployments need nothing here. An entry whose `id` matches a built-in **replaces
it wholesale** — nothing is merged.

```toml
[[clients]]
id = "0011223344556677"                 # 16 hex characters
name = "Thunderbird"
redirect_uris = ["https://mail.example.com/oauth"]
allowed_scopes = "https://identity.thunderbird.net/apps/sync"
trusted = true
can_grant = true
public_client = true                    # PKCE required, no client secret
```

`allowed_scopes` has to be complete: a scope a client asks for and is not
registered for is **dropped**, not granted, which is stricter than upstream's
default and is
{ref}`argued for here <divergence-strict-scope-validation>`. A relier
that mysteriously gets a narrower grant than it asked for is usually this.

### `tokenserver_shared_secret`

Leave it out. Upstream requires it because its tokenserver and its storage nodes
are separate deployments that must be told the same string; here they are one
process, and absent an explicit value one is derived from the signing key. Set
it only to pin it independently of that key —
{ref}`why <divergence-tokenserver-secret-derived>`.

## Keys, and what a rotation costs

```sh
uv run fxa-lite keygen              # writes paths.signing_key, mode 0600
uv run fxa-lite keygen --force      # replaces it
```

One RSA-2048 key signs every OAuth access token; `/v1/jwks` publishes its public
half. `keygen` writes it with `os.open(..., 0o600)` and refuses to overwrite an
existing key without `--force`. `serve` warns when it finds the file readable by
anyone else and does not narrow it, because it may be a mount or an injected
secret rather than a file this process owns.

There is no `keygen` on startup, in the container or anywhere else. A server
that silently mints a key when one is missing looks like it recovered from a
volume that failed to mount, while having invalidated every outstanding token.
It exits 1 and tells you to run `keygen`.

**Rotating** costs two things at once, because the signing key is also what the
tokenserver secret is derived from:

* every outstanding access token stops verifying, and
* every outstanding Sync token stops verifying.

Both cost a client one extra round trip — a refresh, and a new tokenserver
exchange — and neither costs a re-sign-in, because sign-in state is the session
token and that is unaffected. To make the first of the two free, keep the old
key's *public* JWK:

```sh
python -c 'import json,sys; k=json.load(open("signing-key.json")); \
    json.dump({f: k[f] for f in ("kty","n","e","kid","alg","use")}, sys.stdout)' \
    > retired-key.json
uv run fxa-lite keygen --force
```

and point `paths.retired_key` at it. `/v1/jwks` then publishes both, tokens
signed by the old key keep verifying until they expire, and nothing new is ever
signed with it. Delete the retired key once `ttl.access_token` has passed.

## TLS and the proxy

**TLS is required, and it terminates at exactly `public_url`.** This is not
hardening advice, it is a functional requirement:

* The sign-in page derives the password with `crypto.subtle`, which browsers
  expose only in a **secure context**. `http://localhost` and `http://127.0.0.1`
  qualify. A LAN address like `http://192.168.1.10:9000` does **not**, and the
  page dies at `crypto.subtle is undefined` after everything else has gone
  right. Serving a household off a LAN address therefore needs real TLS.
* `identity.fxaccounts.allowHttp` belongs on a loopback test and nowhere else.

`deploy/nginx.conf.example` is a working configuration. Copy it to
`deploy/nginx.conf`, edit the four marked places, and either run it with
`docker compose --profile tls up -d` or hand it to the proxy you already have.
Certificates stay the host's job — `certbot certonly` plus a renewal hook that
reloads the proxy; nothing here issues them.

Three things that config gets right and a hand-written one often does not:

**Per-IP rate limiting is not optional.** The `limit_req_zone` over the three
password endpoints ships uncommented. fxa-lite's own throttle counts failures
per account and cannot count per IP, because behind a proxy every client is
`127.0.0.1`. This tier is the only one that can, and the thing it is protecting
is a 64 MiB scrypt per request.

**The body limit has to match.** Sync storage advertises
`max_request_bytes` in `/info/configuration` and Firefox sizes its batch uploads
to it. A `client_max_body_size` below that number turns a legal upload into a
413 the client cannot interpret; `tests/test_docker.py` asserts the example
config and the advertised limit agree.

**No path prefix.** Serve fxa-lite at `/` of its own hostname. A proxy that
mounts it under `/fxa/` breaks every HAWK signature, because the client signs
the path the tokenserver handed it and the tokenserver builds that from
`public_url`.

## The container

```{include} ../README.md
:start-after: <!-- include: docker-quickstart -->
:end-before: <!-- end: docker-quickstart -->
```

Everything lives in one volume mounted at `/data` — `fxa.toml`, `fxa.sqlite`,
`signing-key.json` — found through `FXA_LITE_CONFIG=/data/fxa.toml`, because
relative paths in the config resolve against the directory holding it.

Three caveats, in the order they bite:

1. **`public_url` is the external `https://` origin**, not the container's
   address. The container binds `0.0.0.0`; compose publishes `127.0.0.1:9000`
   on the host, in front of whatever terminates TLS.
2. **A bind mount must be chowned to uid 1000**, the uid the container runs as.
   A named volume on the box's own disk needs nothing and is the safe default.
3. **`/data` must be local.** See above: SQLite over a network filesystem is the
   one way to lose data here.

`docker compose --profile tls up -d` additionally starts the nginx described
above. `scripts/docker-smoke.sh` builds the image and drives the whole bootstrap
against a throwaway volume, including the assertions that no deployment secret
is in a layer and that `keygen` inside the container writes the key 0600.

Development is deliberately not containerised: `uv run fxa-lite serve --reload`
is faster than any bind-mount-and-watch arrangement, and the JavaScript tests
need `node`, which has no business in a deployment image.

## Accounts

```sh
uv run fxa-lite account add you@example.com     # prompts twice; 12 characters minimum
uv run fxa-lite account list
uv run fxa-lite account remove you@example.com
```

There is no signup page and there will not be one. `remove` deletes the account,
its sessions, its devices and — because `sync_users.fxa_uid` is a real foreign
key here where upstream has only a string
({ref}`why <divergence-sync-users-real-foreign-key>`) — its Sync storage
along with it.

`--password` exists and puts the password in your shell history and in the
process list. Use it for scripts you have thought about and not otherwise.

**The password is the whole authenticator.** It is also, through PBKDF2 and
HKDF, the key that encrypts Sync data: `kB` never leaves the browser in a form
the server can read, so a forgotten password is unrecoverable and there is no
reset flow. That is both a cost and a security property — there is no reset flow
to attack either. Use a passphrase, and keep it somewhere.

## Backup

Copy the directory holding `fxa.toml`, `fxa.sqlite` and `signing-key.json`.
There is nothing else. Copy it while the server is stopped, or use
`sqlite3 fxa.sqlite ".backup out.sqlite"` — the database runs in WAL mode, so a
naive copy of the `.sqlite` file alone while it is running can miss committed
transactions sitting in `-wal`.

What each loss costs:

**The database, kept by someone else.** Session token ids are the credential a
client presents, so a copy is a set of live sessions until they are destroyed;
this is upstream's design and the reason codes and refresh tokens are stored
under SHA-256 while these are not. It also holds `kA` in the clear. It does
**not** hold `kB`, so it is not enough to read anyone's Sync data — that needs
the password.

**The database, lost.** The accounts are gone, and so is the synced data: the
BSOs live in that same file. Recreating an account with `account add` mints a
fresh `kB` even when the password is identical, so the browsers see a server
they have never met, sign in again and upload what they still hold locally.
Anything only one browser had, and that browser is also gone, is gone. Browsers
are not the backup; this file is.

**The signing key, lost.** Every outstanding access token and Sync token stops
verifying. Run `keygen`, restart, and clients recover on their next request.
Nothing needs to be re-provisioned.

**The signing key, kept by someone else.** They can mint access tokens for any
uid they know, which is a full compromise of the OAuth and Sync tiers. It cannot
give them `kB`. Rotate it (above), and treat any database copy taken at the same
time as a copy of the accounts.

## Security, and what the deployment owes

The README's **Security** section is the operator's list, and it is the one to
read before forwarding a port: what is on by default, what the deployment is
required to provide, and the five risks that were accepted rather than fixed,
each with the reasoning. `AUDIT.md` is the phase-10 findings list behind it.

Three of those items are answered here rather than in the code, and all three
are in this page: TLS terminated at `public_url`, per-IP rate limiting at the
proxy, and the signing key's mode.
