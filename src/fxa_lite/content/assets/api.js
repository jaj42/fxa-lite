/**
 * The slice of the accounts and OAuth API this page calls.
 *
 * Same origin as the page, so every path is relative and there is no CORS
 * preflight to think about.  Errors arrive as the FxA envelope
 * (`{code, errno, error, message}`) and are raised as `ApiError`, whose
 * `errno` is the part worth branching on.
 */

import * as fxaCrypto from './crypto.js';

/** An FxA error envelope, thrown. */
export class ApiError extends Error {
  constructor(status, body) {
    super(body.message || `Request failed with ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.errno = body.errno;
    this.body = body;
  }
}

async function request(method, path, { body, authorization } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
  }
  if (authorization) {
    headers.authorization = authorization;
  }
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    // The session token is in memory, not in a cookie; sending credentials
    // would only widen what this request carries.
    credentials: 'omit',
  });
  if (response.status === 204) {
    return null;
  }
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(response.status, { message: `Unreadable response (${response.status})` });
  }
  if (!response.ok) {
    throw new ApiError(response.status, payload);
  }
  return payload;
}

async function authed(method, path, token, kind, body) {
  return request(method, path, {
    body,
    authorization: await fxaCrypto.bearerHeader(token, kind),
  });
}

/**
 * `POST /v1/account/login?keys=true`.
 *
 * Returns the server's answer plus the `unwrapBKey` that never left this page,
 * because the two are only useful together.
 */
export async function login(email, password, { keys = true } = {}) {
  const credentials = await fxaCrypto.getCredentials(email, password);
  const account = await request('POST', `/v1/account/login${keys ? '?keys=true' : ''}`, {
    body: { email, authPW: fxaCrypto.bytesToHex(credentials.authPW) },
  });
  return { ...account, unwrapBKey: credentials.unwrapBKey };
}

/**
 * `GET /v1/account/keys` — fetch the bundle, check its MAC, unwrap `kB`.
 *
 * The token is single-use: the server destroys it as it answers, so this can
 * be called exactly once per sign-in.
 */
export async function accountKeys(keyFetchToken, unwrapBKey) {
  const credentials = await fxaCrypto.deriveTokenCredentials(keyFetchToken, 'keyFetchToken');
  const { bundle } = await authed('GET', '/v1/account/keys', keyFetchToken, 'keyFetchToken');
  const { kA, wrapKb } = await fxaCrypto.unbundleKeyFetchResponse(credentials.bundleKey, bundle);
  return { kA, kB: fxaCrypto.unwrapKb(wrapKb, unwrapBKey) };
}

/** `POST /v1/account/scoped-key-data` — the rotation metadata for a scope list. */
export function scopedKeyData(sessionToken, clientId, scope) {
  return authed('POST', '/v1/account/scoped-key-data', sessionToken, 'sessionToken', {
    client_id: clientId,
    scope,
  });
}

/** `POST /v1/oauth/authorization` — a signed-in session becomes a code. */
export function authorization(sessionToken, params) {
  return authed('POST', '/v1/oauth/authorization', sessionToken, 'sessionToken', params);
}
