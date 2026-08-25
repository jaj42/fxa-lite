# Pointing a browser at it

Everything is served from one origin, so `public_url` is the only value any
client needs. Below it is `https://fxa.example.com`.

| Client | What you set | Derived from `public_url` how |
|---|---|---|
| Firefox Desktop | `identity.fxaccounts.autoconfig.uri` | the origin, unchanged |
| Firefox for Android (Fenix) | *Custom Mozilla account server* | the origin, unchanged |
| Firefox for Android (Fenix) | *Custom Sync server* | the origin **plus** `/token/1.0/sync/1.5` |
| Firefox for iOS | — | untested; see [below](#firefox-for-ios) |

That asymmetry in the middle two rows is the thing that catches people out, and
it has a reason: the account field is an **origin**, from which the app reads
the discovery document exactly as desktop does, while the sync field is a
**full tokenserver URL**. Upstream those are two separate deployments, and the
field predates discovery.

## Firefox Desktop

A fresh profile, `about:config`:

```{include} ../README.md
:start-after: <!-- include: desktop-prefs -->
:end-before: <!-- end: desktop-prefs -->
```

The first pref is enough on its own. Firefox reads
`/.well-known/fxa-client-configuration` from that origin and finds the accounts,
OAuth, profile and tokenserver endpoints in it — which is why the prefix layout
in [Architecture](architecture.md) is ours to choose.

If autoconfig misbehaves, the explicit alternative is four prefs instead of one:
`identity.fxaccounts.auth.uri` (`<origin>/v1`),
`identity.fxaccounts.remote.oauth.uri` (`<origin>/v1`),
`identity.fxaccounts.remote.profile.uri` (`<origin>/profile/v1`) and
`identity.sync.tokenserver.uri` (`<origin>/token/1.0/sync/1.5`). Setting them is
also a way to find out whether autoconfig is the problem.

### Two things that will otherwise cost you an evening

**Plain HTTP works on `localhost` and nowhere else.** The sign-in page derives
your password with `crypto.subtle`, which browsers expose only in a *secure
context*. `http://localhost` and `http://127.0.0.1` qualify; a LAN address like
`http://192.168.1.10:9000` does not, and the page fails with
`crypto.subtle is undefined` after everything else has gone right. Serving
anything other than loopback means real TLS — see
[TLS and the proxy](running.md#tls-and-the-proxy).

**Turn HTTPS-Only mode off for that origin**, or Firefox upgrades the request
before it leaves the browser and the server sees a TLS handshake on a plaintext
socket. The symptom is `Invalid HTTP request received` from uvicorn with no
access-log line at all, which reads like a protocol bug and is not one. Loopback
is exempt from the upgrade; a LAN address is not.

### When it does not work

`about:sync-log` holds Sync's own logs, and the Sync panel in
`about:preferences#sync` says whether the account tier or the storage tier is
unhappy. For the account side, set `identity.fxaccounts.loglevel` and
`identity.fxaccounts.log.appender.dump` to `Debug` and read the Browser Console
(<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>J</kbd>).

On the server, `fxa-lite serve --log-level debug` writes every request and
response with its body, credentials redacted. That pair — the browser saying
what it sent and the server saying what it made of it — is what most of
[phase 8](flows.md) was.

## Firefox for Android (Fenix)

There is no `about:config`. The equivalent is behind the secret menu:

**Settings → About Firefox → tap the logo five times → Settings → Sync Debug.**

```{include} ../README.md
:start-after: <!-- include: android-fields -->
:end-before: <!-- end: android-fields -->
```

Older builds call the first one *Custom Firefox Account server*. Leave *Custom
Push server* empty — push notifications are out of scope, and the device
routes say so in the protocol's own words rather than by failing.

**Set both fields before signing in**, and set them on a profile that is not
already signed in. Fenix reads them when it builds its account manager, and an
account already connected to Mozilla's servers does not migrate.

A phone needs TLS before any of this: `crypto.subtle` again, and a phone has no
loopback exemption to fall back on.

### What is still unestablished

Android **signs in and syncs** — tokenserver, `meta/global`, `crypto/keys`, and
uploads of clients, prefs, tabs, bookmarks, addons and history. That is a
result, not a reading of the code. Three narrower questions around it are not,
and this page says so rather than guessing:

*Whether the second field is needed at all.* The discovery document already
advertises `sync_tokenserver_base_url`, so an app that prefers discovery when
the override is blank would need one field, not two. Nobody has tried it with
the field empty. Setting it costs nothing and is known to work, so it is still
the instruction. What *is* settled is the spelling: the client normalises the
override by trimming a trailing `/1.0/sync/1.5`
(`Config::normalize_token_server_url` in `mozilla/application-services`), so the
origin and the full URL are the same value to it, and neither can be the reason
a sign-in fails.

*What the fields do to an already-signed-in profile.* Whether they require
signing out first, and whether the app restarts, is untested. Sign out first.

*Whether "Use New React Mozilla Account page" changes which path the app opens.*
The content server answers a fixed table of paths, and a path outside it is a
404 in a web view. The flow described here was seen with that setting at its
default.

(fxa-lite id `a2270f727f45f648`, redirect `<public_url>/oauth/success/<client_id>`.)

## Firefox for iOS

Registered as an OAuth client (`1b1a3e44c54fbb58`) with the same redirect shape,
because the client table came from upstream's and dropping it would have been a
choice too. Whether a shipping build can be pointed at a custom account server
at all is **unknown**: iOS has no `about:config` and no secret menu equivalent
that has been found, and nobody has tried it against this server.

Assume for now that it cannot. If you establish otherwise, the fields belong in
the table at the top of this page.

## Anything else

The client table is a config file — see
[`[[clients]]`](running.md#clients) — so a relier that speaks OAuth 2.0 with
PKCE can be registered. Two things to know before trying:

* `allowed_scopes` must list every scope the client will ask for. An
  unregistered scope is **dropped**, not granted, which is stricter than
  upstream's default;
  {ref}`the argument <divergence-strict-scope-validation>`.
* A key-bearing scope — `https://identity.mozilla.com/apps/oldsync` and
  Thunderbird's equivalent — is checked *before* that trim, so asking for one
  you may not have is an error rather than a quiet omission. That is upstream's
  rule, and it is the one that stops an unregistered client from asking for the
  Sync key.
