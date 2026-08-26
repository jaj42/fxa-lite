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

## Where each client files the other's records

Sync moves records; it does not move the shelf they sit on. Both browsers keep
their *own* things in the place you expect and the *other* device's things
somewhere separate, and every report this project has had of "one-way sync" has
so far been that separation rather than the wire.

**Desktop bookmarks on Android.** Firefox for Android roots its bookmark screen
at the `mobile` folder, which is where bookmarks made on the phone go. Anything
made on Desktop lives in `menu`, `toolbar` or `unfiled`, and the phone shows
those under a **Desktop Bookmarks** entry — one level down, not in the list you
land on. They are not missing.

**Android tabs on Desktop.** Look in *Firefox View* (`about:firefoxview`) under
*Tabs from other devices*, or open the **Synced Tabs** sidebar (View → Sidebar →
Synced Tabs). On LibreWolf and other forks that ship Firefox View disabled, the
sidebar is the one that will be there. Either way the phone has to appear in
`about:preferences#sync` first: that list is the `clients` collection, and a
device that is not in it has not uploaded anything for Desktop to show.

**Desktop tabs on Android** are in the tab tray, under its own *Desktop tabs*
heading, on the same principle.

If something really is missing, the server can say so without guessing:
`fxa-lite sync inspect` prints one line per collection with its record count and
when it last changed, and `tabs` and `clients` are one record per device — so
two devices that are both syncing are two rows, and one row is a real finding.

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

**Set the fields before signing in**, and set them on a profile that is not
already signed in: an account that is already connected keeps the server it
connected to, because its config travels in its own persisted state rather than
being re-read from these preferences. Changing either field offers a *Quit
application* button, and taking it is required — see
[below](#what-the-source-settles), where the second field turns
out not to be needed at all.

A phone needs TLS before any of this: `crypto.subtle` again, and a phone has no
loopback exemption to fall back on.

### What the source settles

Android **signs in and syncs** — tokenserver, `meta/global`, `crypto/keys`, and
uploads of clients, prefs, tabs, bookmarks, addons and history. That is a
result from a handset. The three questions that used to sit here were answered
afterwards by reading the code that decides each one; each is a claim about a
pinned commit rather than about a phone, and says which file it came from.

*The **Custom Sync server** field is not needed.* Fenix passes
`overrideSyncTokenServer.ifEmpty { null }` into its `ServerConfig`
(`fenix/.../components/FxaServer.kt`), and with no override
`Config::token_server_endpoint_url` falls back to the
`sync_tokenserver_base_url` this server advertises
(`fxa-client/src/internal/config.rs`). What that URL then needs is supplied by
`fixup_server_url` in `sync15`, which appends `/1.0/sync/1.5` to anything that
does not already end in it — upstream's own unit test asserts that
`https://selfhosted.example.com/token/` becomes
`https://selfhosted.example.com/token/1.0/sync/1.5`, which is exactly the shape
fxa-lite publishes. Every spelling of the field therefore ends at the same URL:
blank, the origin, `<origin>/token`, or the full path, the last because the
override is normalised by *trimming* a trailing `/1.0/sync/1.5`
(`Config::normalize_token_server_url`). The table above keeps the full URL
because that is the value a phone in this household actually synced with; blank
is a reading, and it is the reading of three files that agree.

*The fields do nothing to an already-signed-in profile, and the app has to
restart.* Both are read only where a **new** account is built:
`StorageWrapper.account()` returns `AccountOnDisk.Restored` whenever there is
saved state, and that state is rebuilt with `FirefoxAccount.fromJSONString`,
whose persisted `StateV2` carries its own `config` — the server, and the
tokenserver override, that the account signed in against. The prefs are not
consulted on that path at all. And they are not consulted again in a running
process: changing either one in Sync Debug reveals a *Quit application* item
that calls `exitProcess(0)` (`SyncDebugFragment.kt`), which older builds did by
themselves with the toast *"Mozilla account/Sync server modified. Quitting the
application to apply changes…"*. So: sign out first, set the fields, let it
quit, sign in.

*"Use New React Mozilla Account page" cannot open a path this server does not
serve.* React and Backbone are two renderings of the **same** Express paths
upstream: `routes/react-app/index.js` lists the route groups by name —
`authorization`, `signin`, `oauth/signin` — and `add-routes.js` registers both
apps on each path, picking React when `?showReactApp=true` or when the rollout
flag is on. The lever is a query parameter, never a new path. The entry point
is not the app's choice either: `begin_oauth_flow` opens the
`authorization_endpoint` out of *our* `/.well-known/openid-configuration`, or,
for a re-authentication, `<content_url>/oauth/force_auth` — a literal in
`internal/config.rs` and one of four such literals, all of which
`content/__init__.py:PAGE_PATHS` now serves.

(fxa-lite id `a2270f727f45f648`, redirect `<public_url>/oauth/success/<client_id>`.)

## Firefox for iOS

Registered as an OAuth client (`1b1a3e44c54fbb58`) with the same redirect shape,
because the client table came from upstream's and dropping it would have been a
choice too. Whether a shipping build can be pointed at a custom account server
at all is **unknown**, and unlike the Android questions above it is not a
question the source can answer: iOS has no `about:config` and no secret menu
equivalent that has been found, so the answer is whatever a build allows, and
nobody here has an iPhone to try it on.

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
