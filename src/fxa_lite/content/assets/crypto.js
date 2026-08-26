/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The onepw protocol, in the browser.
 *
 * A port of `fxa-auth-client/lib/crypto.ts` and the scoped-key half of
 * `crypto-relier/src/lib/deriver/`, written against WebCrypto so the password
 * never leaves this page: what travels is `authPW`, one HKDF away from 1000
 * rounds of PBKDF2, and `kB` is unwrapped here and sealed straight back up
 * into a JWE for the browser.
 *
 * Nothing in this module touches `window` or `document`, so it can be loaded
 * outside a page — `tests/js/crypto_kat.mjs` runs it under node against the
 * same known-answer vectors that pin the Python implementation.
 */

const NAMESPACE = 'identity.mozilla.com/picl/v1/';
const V1_ITERATIONS = 1000;

/** `TOKEN_PREFIXES` from `lib/bearer.ts`. */
export const TOKEN_PREFIXES = {
  sessionToken: 'fxs',
  keyFetchToken: 'fxk',
  accountResetToken: 'fxar',
  passwordForgotToken: 'fxpf',
  passwordChangeToken: 'fxpc',
};

export const OLDSYNC_SCOPE = 'https://identity.mozilla.com/apps/oldsync';
const THUNDERBIRD_SYNC_SCOPE = 'https://identity.thunderbird.net/apps/sync';

const encoder = new TextEncoder();

export function utf8(text) {
  return encoder.encode(text);
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('not a hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function b64u(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function xor(a, b) {
  if (a.length !== b.length) {
    throw new Error('xor operands must be the same length');
  }
  return Uint8Array.from(a, (byte, index) => byte ^ b[index]);
}

function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Constant-time equality — used on the key-bundle MAC. */
function equalBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference === 0;
}

/**
 * RFC 5869 HKDF-SHA256.
 *
 * An absent salt is `hashLen` zero bytes, which is both what the RFC specifies
 * and what the Node `hkdf` package does with the `null` the reference server
 * passes. Every derivation below rests on that.
 */
export async function hkdf(ikm, info, length, salt = new Uint8Array(32)) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

/** The namespaced `info` the protocol actually speaks. */
export function kw(name) {
  return utf8(NAMESPACE + name);
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function hmacSha256(key, message) {
  const imported = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, message));
}

/**
 * `crypto.getCredentials` — v1 key stretching.
 *
 * `authPW` is what the server sees; `unwrapBKey` never leaves the client, and
 * without it the `wrapKb` the server hands back is inert.
 */
export async function getCredentials(email, password) {
  const salt = utf8(`${NAMESPACE}quickStretch:${email}`);
  const material = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const stretched = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: V1_ITERATIONS, hash: 'SHA-256' },
      material,
      256
    )
  );
  // Note the lowercase `k` in `unwrapBkey`: it is the wire's spelling, not a typo.
  return {
    authPW: await hkdf(stretched, kw('authPW'), 32),
    unwrapBKey: await hkdf(stretched, kw('unwrapBkey'), 32),
  };
}

/** `deriveHawkCredentials` — 96 bytes of HKDF, sliced in three. */
export async function deriveTokenCredentials(token, kind) {
  const material = await hkdf(hexToBytes(token), kw(kind), 96);
  return {
    id: bytesToHex(material.slice(0, 32)),
    authKey: material.slice(32, 64),
    bundleKey: material.slice(64, 96),
  };
}

/**
 * `bearerHeader` — `Bearer fxs_<id>` and friends.
 *
 * fxa-lite accepts this and the HAWK form equally, and neither verifies a MAC;
 * the Bearer form is the one with nothing to get wrong.
 */
export async function bearerHeader(token, kind) {
  const { id } = await deriveTokenCredentials(token, kind);
  return `Bearer ${TOKEN_PREFIXES[kind]}_${id}`;
}

/** `unbundleKeyFetchResponse`: check the MAC, then undo the one-time pad. */
export async function unbundleKeyFetchResponse(bundleKey, bundle) {
  const payload = hexToBytes(bundle);
  const ciphertext = payload.slice(0, payload.length - 32);
  const mac = payload.slice(payload.length - 32);
  const material = await hkdf(bundleKey, kw('account/keys'), 3 * 32);
  const expected = await hmacSha256(material.slice(0, 32), ciphertext);
  if (!equalBytes(mac, expected)) {
    throw new Error('Bad HMAC on the key bundle');
  }
  const plaintext = xor(ciphertext, material.slice(32, 96));
  return { kA: plaintext.slice(0, 32), wrapKb: plaintext.slice(32, 64) };
}

export function unwrapKb(wrapKb, unwrapBKey) {
  return xor(wrapKb, unwrapBKey);
}

/**
 * `scoped-keys.ts` — the key a relier gets for one scope.
 *
 * Sync is the legacy path: 64 bytes derived from `kB` alone, with a `kid`
 * naming a hash of `kB` and the rotation timestamp in **milliseconds**. Every
 * other scope takes the general path, salted with the uid, and rounds its
 * timestamp to seconds.
 */
export async function deriveScopedKey({
  scope,
  kb,
  uid,
  keyRotationSecret,
  keyRotationTimestamp,
}) {
  if (scope === OLDSYNC_SCOPE || scope === THUNDERBIRD_SYNC_SCOPE) {
    const material = await hkdf(kb, kw('oldsync'), 64);
    return {
      kty: 'oct',
      scope,
      k: b64u(material),
      kid: `${keyRotationTimestamp}-${b64u((await sha256(kb)).slice(0, 16))}`,
    };
  }
  const material = await hkdf(
    concat(kb, hexToBytes(keyRotationSecret)),
    utf8(`${NAMESPACE}scoped_key\n${scope}`),
    48,
    hexToBytes(uid)
  );
  return {
    kty: 'oct',
    scope,
    k: b64u(material.slice(16, 48)),
    kid: `${Math.round(keyRotationTimestamp / 1000)}-${b64u(material.slice(0, 16))}`,
  };
}

/** NIST SP 800-56A single-step KDF, as RFC 7518 §4.6.2 profiles it. */
export async function concatKdf(shared, algorithm, apu = new Uint8Array(0), apv = new Uint8Array(0), length = 32) {
  const prefixed = (value) => concat(uint32(value.length), value);
  const suffix = concat(prefixed(algorithm), prefixed(apu), prefixed(apv), uint32(length * 8));
  const blocks = [];
  let produced = 0;
  for (let counter = 1; produced < length; counter++) {
    const block = await sha256(concat(uint32(counter), shared, suffix));
    blocks.push(block);
    produced += block.length;
  }
  return concat(...blocks).slice(0, length);
}

function uint32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function publicJwk(jwk) {
  // `exportKey` hands back `ext` and `key_ops` too; the header carries only
  // the four members that describe the point.
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/**
 * Compact JWE, `alg=ECDH-ES`, `enc=A256GCM` — what `keys_jwe` is.
 *
 * The recipient is the browser's own P-256 public key, handed to this page as
 * the base64url `keys_jwk` query parameter. The server never opens this: it
 * stores the blob on the code row and echoes it back at token time.
 */
export async function encryptJweEcdhEs(recipientJwk, plaintext) {
  const recipient = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: recipientJwk.x, y: recipientJwk.y },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256)
  );
  const cek = await concatKdf(shared, utf8('A256GCM'));
  const header = {
    alg: 'ECDH-ES',
    enc: 'A256GCM',
    epk: publicJwk(await crypto.subtle.exportKey('jwk', ephemeral.publicKey)),
  };
  const protectedHeader = b64u(utf8(JSON.stringify(header)));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const { ciphertext, tag } = await sealA256Gcm(protectedHeader, cek, iv, plaintext);
  // Direct key agreement wraps no key, so the second segment is empty.
  return `${protectedHeader}..${b64u(iv)}.${b64u(ciphertext)}.${b64u(tag)}`;
}

/**
 * The AEAD half of a compact JWE, split out because it is the half a
 * known-answer vector can pin (RFC 7516 appendix A.1).
 *
 * The AAD is the ASCII base64url protected header, and the 16-byte tag travels
 * as its own compact segment rather than glued to the ciphertext.
 */
export async function sealA256Gcm(protectedHeader, cek, iv, plaintext) {
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: utf8(protectedHeader), tagLength: 128 },
      key,
      plaintext
    )
  );
  return {
    ciphertext: sealed.slice(0, sealed.length - 16),
    tag: sealed.slice(sealed.length - 16),
  };
}

/** RFC 7636 S256: a random verifier and the challenge derived from it. */
export async function pkcePair() {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: b64u(await sha256(utf8(verifier))) };
}

export function randomB64u(length = 16) {
  return b64u(crypto.getRandomValues(new Uint8Array(length)));
}
