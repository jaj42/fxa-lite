/**
 * The sign-in page: password in, WebChannel messages out.
 *
 * One document serves every content-server route; which view it shows is
 * decided here from `location.pathname`, the way the reference SPA does it.
 *
 * The sign-in flow follows `fxa-settings/src/pages/Signin/utils.ts`.  Two
 * rules in there cost days if missed, and both are enforced below:
 *
 *  * `fxaccounts:login` **must** be sent before `fxaccounts:oauth_login`;
 *  * on an OAuth flow `keyFetchToken` and `unwrapBKey` must be **left out** of
 *    `fxaccounts:login` — the scoped keys already travel inside `keys_jwe`,
 *    and sending them twice causes intermittent Sync disconnects.
 */

import * as fxaCrypto from './crypto.js';
import * as api from './api.js';
import * as channel from './webchannel.js';

const WEBCHANNEL_REDIRECT = 'urn:ietf:wg:oauth:2.0:oob:oauth-redirect-webchannel';
const PKCE_METHOD = 'S256';

const params = new URLSearchParams(window.location.search);

/** Everything the browser told us in the URL it opened. */
const flow = {
  clientId: params.get('client_id'),
  state: params.get('state'),
  scope: params.get('scope'),
  service: params.get('service'),
  context: params.get('context'),
  action: params.get('action'),
  email: params.get('email'),
  redirectUri: params.get('redirect_uri'),
  accessType: params.get('access_type') || 'offline',
  codeChallenge: params.get('code_challenge'),
  codeChallengeMethod: params.get('code_challenge_method'),
  keysJwk: params.get('keys_jwk'),
};

const isOAuth = Boolean(flow.clientId);
/**
 * Both Sync contexts speak the WebChannel: `oauth_webchannel_v1` is today's
 * OAuth flow, `fx_desktop_v3` the older one where the browser fetches the keys
 * itself from a `keyFetchToken` we hand it.
 */
const isWebChannel =
  flow.context === 'oauth_webchannel_v1' || (flow.context || '').startsWith('fx_desktop_');
const isSync = flow.service === 'sync' || flow.context === 'oauth_webchannel_v1';

/** What the browser answered to `fxaccounts:fxa_status`, once we have asked. */
let browserStatus;

// --------------------------------------------------------------------------
// A very small DOM helper. Every node is created and every string becomes a
// text node, so no value from the URL or from the server is ever parsed as
// markup — `test_the_page_never_assigns_markup` is what keeps that true.
// --------------------------------------------------------------------------

function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) {
      continue;
    }
    if (name.startsWith('on')) {
      node.addEventListener(name.slice(2), value);
    } else {
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) {
      continue;
    }
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function render(...children) {
  const root = document.getElementById('app');
  root.replaceChildren(...children.flat().filter(Boolean));
  return root;
}

// --------------------------------------------------------------------------
// Views
// --------------------------------------------------------------------------

function serviceName() {
  if (isSync) {
    return 'Firefox Sync';
  }
  return flow.clientId ? `client ${flow.clientId}` : 'this server';
}

function signInView() {
  const status = el('p', { class: 'status', role: 'status', 'aria-live': 'polite' });
  const email = el('input', {
    id: 'email',
    type: 'email',
    name: 'email',
    autocomplete: 'username',
    spellcheck: 'false',
    autocapitalize: 'none',
    required: true,
    value: flow.email || browserStatus?.signedInUser?.email || '',
  });
  const password = el('input', {
    id: 'password',
    type: 'password',
    name: 'password',
    autocomplete: 'current-password',
    required: true,
  });
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Sign in');

  const form = el(
    'form',
    {
      novalidate: true,
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        status.textContent = 'Signing in…';
        status.className = 'status';
        try {
          await signIn(email.value.trim(), password.value);
          render(successView());
        } catch (error) {
          status.textContent = describe(error);
          status.className = 'status error';
          submit.disabled = false;
          password.value = '';
          password.focus();
        }
      },
    },
    el('label', { for: 'email' }, 'Email'),
    email,
    el('label', { for: 'password' }, 'Password'),
    password,
    submit
  );

  return [
    el('h1', {}, 'Sign in'),
    el('p', { class: 'subtitle' }, `to continue to ${serviceName()}`),
    form,
    status,
    isWebChannel && browserStatus === undefined
      ? el(
          'p',
          { class: 'note' },
          'This browser is not answering on the WebChannel. Check that ' +
            'webchannel.allowObject.urlWhitelist in about:config lists this origin.'
        )
      : null,
  ];
}

function successView() {
  return [
    el('h1', {}, 'Signed in'),
    el(
      'p',
      { class: 'subtitle' },
      isWebChannel
        ? 'Firefox has been handed the keys. You can close this tab.'
        : 'You are signed in. You can close this tab.'
    ),
  ];
}

function settingsView() {
  const uid = browserStatus?.signedInUser?.uid;
  return [
    el('h1', {}, 'Account'),
    el(
      'p',
      { class: 'subtitle' },
      browserStatus?.signedInUser?.email
        ? `Signed in as ${browserStatus.signedInUser.email}.`
        : 'No account is connected to this browser.'
    ),
    el(
      'p',
      { class: 'note' },
      'fxa-lite has no account management: passwords, email addresses and ' +
        'account removal are handled with the fxa-lite command line on the ' +
        'machine holding the database.'
    ),
    uid
      ? el(
          'button',
          {
            class: 'secondary',
            onclick: (event) => {
              channel.logout(uid);
              event.target.disabled = true;
              event.target.textContent = 'Disconnected';
            },
          },
          'Disconnect this browser'
        )
      : null,
  ];
}

function unavailableView(title, detail) {
  return [el('h1', {}, title), el('p', { class: 'subtitle' }, detail)];
}

// --------------------------------------------------------------------------
// The flow
// --------------------------------------------------------------------------

/**
 * Sign in, and tell the browser about it.
 *
 * The order is upstream's: ask permission to link *before* creating a session,
 * so a user who cancels the browser's dialog leaves no session token behind.
 */
async function signIn(email, password) {
  if (isWebChannel && browserStatus !== undefined && !(await channel.canLinkAccount(email))) {
    throw new Error('Sign-in was cancelled in the browser.');
  }

  // The OAuth flow needs `kB` here to build `keys_jwe`; the older Sync flow
  // needs the `keyFetchToken` itself, because the browser fetches the keys.
  const wantsKeys = !isOAuth || Boolean(flow.keysJwk);
  const account = await api.login(email, password, { keys: wantsKeys });

  const services = isSync
    ? { sync: { offeredEngines: offeredEngines(), declinedEngines: [] } }
    : undefined;

  if (!isOAuth) {
    // `fx_desktop_v3`: hand over the key material and let the browser do the
    // rest. These are the fields `fx-sync-channel.js` requires; without every
    // one of them the browser drops the message on the floor.
    channel.login({
      email,
      uid: account.uid,
      sessionToken: account.sessionToken,
      verified: true,
      verifiedCanLinkAccount: true,
      keyFetchToken: account.keyFetchToken,
      unwrapBKey: fxaCrypto.bytesToHex(account.unwrapBKey),
      services,
    });
    return;
  }

  const grant = await authorize(email, account);

  // Must precede `fxaccounts:oauth_login`, and must not carry key material.
  channel.login({
    email,
    uid: account.uid,
    sessionToken: account.sessionToken,
    verified: true,
    verifiedCanLinkAccount: true,
    services,
  });
  channel.oauthLogin({
    action: 'signin',
    code: grant.code,
    // The bare sentinel, as `sendOAuthResultToRelier` sends it: the browser
    // reads `code` and `state` off this message, not off a URL.
    redirect: WEBCHANNEL_REDIRECT,
    // Always the state the browser passed in.
    state: flow.state,
    scope: grant.scope,
    offeredSyncEngines: offeredEngines(),
    declinedSyncEngines: [],
  });

  if (!isWebChannel && grant.redirect) {
    window.location.href = grant.redirect;
  }
}

/** Everything between a session token and an authorization code. */
async function authorize(email, account) {
  const request = {
    client_id: flow.clientId,
    state: flow.state || fxaCrypto.randomB64u(),
    response_type: 'code',
    access_type: flow.accessType,
  };
  if (flow.scope) {
    request.scope = flow.scope;
  } else if (flow.service) {
    // ADR 0049: the browser may send `service=sync` and no scope at all, and
    // the server resolves it.
    request.service = flow.service;
  }
  if (flow.redirectUri) {
    request.redirect_uri = flow.redirectUri;
  }
  if (flow.codeChallenge) {
    request.code_challenge = flow.codeChallenge;
    request.code_challenge_method = flow.codeChallengeMethod || PKCE_METHOD;
  }

  if (flow.keysJwk) {
    request.keys_jwe = await buildKeysJwe(account);
  }
  return api.authorization(account.sessionToken, request);
}

/**
 * Derive the scoped keys for this grant and seal them to the browser's key.
 *
 * `keys_jwk` is the browser's P-256 public key, base64url-encoded in the URL.
 * The server never opens the result: it stores the blob against the code and
 * hands it back at token time, so this page is the only thing that ever sees
 * both `kB` and the scoped keys.
 */
async function buildKeysJwe(account) {
  const scope = flow.scope || (flow.service === 'sync' ? fxaCrypto.OLDSYNC_SCOPE : '');
  if (!scope) {
    return undefined;
  }
  const metadata = await api.scopedKeyData(account.sessionToken, flow.clientId, scope);
  const identifiers = Object.keys(metadata);
  if (identifiers.length === 0) {
    // Nothing in the requested scope carries a key. Not an error: the grant is
    // simply keyless.
    return undefined;
  }

  const { kB } = await api.accountKeys(account.keyFetchToken, account.unwrapBKey);
  const keys = {};
  for (const identifier of identifiers) {
    keys[identifier] = await fxaCrypto.deriveScopedKey({
      scope: identifier,
      kb: kB,
      uid: account.uid,
      keyRotationSecret: metadata[identifier].keyRotationSecret,
      keyRotationTimestamp: metadata[identifier].keyRotationTimestamp,
    });
  }
  const recipient = JSON.parse(new TextDecoder().decode(fxaCrypto.unb64u(flow.keysJwk)));
  return fxaCrypto.encryptJweEcdhEs(recipient, fxaCrypto.utf8(JSON.stringify(keys)));
}

/**
 * The engines this browser says it can sync.
 *
 * There is no "choose what to sync" screen here, so nothing is ever declined:
 * we offer back exactly what the browser offered us, which is what upstream
 * settled on in June 2025 when it dropped the screen too.
 */
function offeredEngines() {
  return browserStatus?.capabilities?.engines || [];
}

function describe(error) {
  if (error?.name === 'ApiError') {
    return error.message;
  }
  return error?.message || 'Something went wrong. Try again.';
}

// --------------------------------------------------------------------------
// Entry point
// --------------------------------------------------------------------------

async function main() {
  const path = window.location.pathname.replace(/\/+$/, '') || '/';

  if (path.startsWith('/oauth/success/')) {
    // The mobile browsers land here after a redirect flow and read the code
    // off the URL themselves; there is nothing left for this page to do.
    render(...successView());
    return;
  }

  if (path === '/pair' || path.startsWith('/pair/') || path === '/connect_another_device') {
    render(
      ...unavailableView(
        'Not available',
        'Device pairing needs a channel server, which fxa-lite does not run. ' +
          'Sign in on the other device with the same email and password instead.'
      )
    );
    return;
  }

  if (isWebChannel) {
    // Asked before anything is rendered: the answer decides the prefilled
    // email, the engine list, and whether a browser is listening at all.
    browserStatus = await channel.fxaStatus({
      service: flow.service || 'sync',
      context: flow.context,
      isPairing: false,
    });
  }

  if (path === '/settings' || path.startsWith('/settings/')) {
    render(...settingsView());
    return;
  }

  render(...signInView());
  const email = document.getElementById('email');
  (email.value ? document.getElementById('password') : email).focus();
}

main().catch((error) => {
  render(el('h1', {}, 'Something went wrong'), el('p', { class: 'status error' }, describe(error)));
});
