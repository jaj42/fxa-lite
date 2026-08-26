/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The WebChannel: how this page talks to the browser it is running inside.
 *
 * A port of `fxa-settings/src/lib/channels/firefox.ts`, minus pairing and the
 * commands fxa-lite has nothing to say about.  Firefox only listens on an
 * origin listed in `webchannel.allowObject.urlWhitelist`; without that pref
 * every message here is dispatched into a void and silently ignored.
 *
 * Two details are load-bearing:
 *
 * * the `detail` of `WebChannelMessageToChrome` must be a **string** for
 *   Desktop and Fennec, and an object for Firefox iOS
 *   (bugzilla 1275616 / 1238128);
 * * the reply listener has to be attached before the send, so every request
 *   sends inside a `requestAnimationFrame` — otherwise a fast browser answers
 *   before anyone is listening.
 */

export const Command = {
  FxAStatus: 'fxaccounts:fxa_status',
  Login: 'fxaccounts:login',
  Logout: 'fxaccounts:logout',
  OAuthLogin: 'fxaccounts:oauth_login',
  CanLinkAccount: 'fxaccounts:can_link_account',
};

const CHANNEL_ID = 'account_updates';
//: `DEFAULT_SEND_TIMEOUT_LENGTH_MS`. Long enough for a slow browser, short
//: enough that a page opened outside Firefox is not stuck on it.
const DEFAULT_TIMEOUT_MS = 500;
//: `fxa_status` is the first message of the flow and answers a question the
//: browser may have to build an answer for, so it gets longer than the rest.
const STATUS_TIMEOUT_MS = 2000;

let messageIdSuffix = 0;

function createMessageId() {
  // Two messages created in the same millisecond would otherwise collide.
  return `${Date.now()}${++messageIdSuffix}`;
}

function isFirefoxIos() {
  return navigator.userAgent.toLowerCase().includes('fxios');
}

function formatEventDetail(command, data, messageId) {
  const detail = { id: CHANNEL_ID, message: { command, data, messageId } };
  return isFirefoxIos() ? detail : JSON.stringify(detail);
}

/** Fire and forget. Most of the protocol is this. */
export function send(command, data) {
  window.dispatchEvent(
    new CustomEvent('WebChannelMessageToChrome', {
      detail: formatEventDetail(command, data, createMessageId()),
    })
  );
}

/**
 * Send and wait for the browser's reply on `WebChannelMessageToContent`.
 *
 * Resolves with `undefined` on timeout rather than rejecting: a browser that
 * does not implement a command is a normal condition, and every caller here
 * has a sensible thing to do without an answer.
 */
export function request(command, data, timeout = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let timer;

    const listener = (event) => {
      let detail;
      try {
        detail = typeof event.detail === 'string' ? JSON.parse(event.detail) : event.detail;
      } catch {
        return;
      }
      if (!detail || detail.id !== CHANNEL_ID || !detail.message) {
        return;
      }
      const message = detail.message;
      if (message.command !== command) {
        return;
      }
      finish(message.error || message.data?.error ? undefined : (message.data ?? message.params));
    };

    const finish = (value) => {
      window.clearTimeout(timer);
      window.removeEventListener('WebChannelMessageToContent', listener);
      resolve(value);
    };

    window.addEventListener('WebChannelMessageToContent', listener);
    timer = window.setTimeout(() => finish(undefined), timeout);
    // The listener is attached above; the send waits a frame so it cannot be
    // beaten by a synchronous reply.
    window.requestAnimationFrame(() => send(command, data));
  });
}

/**
 * `fxaccounts:fxa_status` — who is signed in, and what can this browser sync?
 *
 * The answer's `capabilities.engines` is the list we later echo back as
 * `offeredEngines`; an undefined answer means "no browser is listening", which
 * is how this page detects it was opened in something other than Firefox.
 */
export function fxaStatus({ service, context, isPairing = false }) {
  return request(Command.FxAStatus, { service, context, isPairing }, STATUS_TIMEOUT_MS);
}

/**
 * `fxaccounts:can_link_account` — may this email replace the one already here?
 *
 * The browser puts up a dialog and answers `{ok}`. Upstream treats a missing
 * answer as consent, because an older browser prompts after the fact instead;
 * so does this.
 */
export async function canLinkAccount(email) {
  const response = await request(Command.CanLinkAccount, { email });
  return response ? response.ok !== false : true;
}

export function login(data) {
  send(Command.Login, data);
}

export function oauthLogin(data) {
  send(Command.OAuthLogin, data);
}

export function logout(uid) {
  send(Command.Logout, { uid });
}
