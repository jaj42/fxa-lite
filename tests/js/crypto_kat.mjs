/**
 * Runs the browser crypto under node against the project's known-answer vectors.
 *
 * `src/fxa_lite/content/assets/crypto.js` is the one part of fxa-lite that
 * cannot be exercised from pytest directly, and it is also the part where a
 * mistake is invisible until Firefox silently fails to sync.  It imports
 * nothing from the DOM, so node can load it and compute the same answers the
 * Python KATs pin — see `tests/test_content_crypto.py`, which drives this.
 *
 * Reads a job on stdin, writes the computed values to stdout as JSON; every
 * comparison is made on the Python side so a mismatch shows up as a pytest
 * diff rather than as a message from a subprocess.
 *
 *   node crypto_kat.mjs <path to crypto.js>  < job.json  > results.json
 */

import { pathToFileURL } from 'node:url';

const fxaCrypto = await import(pathToFileURL(process.argv[2]).href);
const { bytesToHex, b64u, hexToBytes, utf8 } = fxaCrypto;

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const job = await readStdin();
const results = {};

results.credentials = await Promise.all(
  job.credentials.map(async ({ name, email, password }) => {
    const { authPW, unwrapBKey } = await fxaCrypto.getCredentials(email, password);
    return { name, auth_pw: bytesToHex(authPW), unwrap_b_key: bytesToHex(unwrapBKey) };
  })
);

results.derivations = await Promise.all(
  job.derivations.map(async ({ name, token_type, data }) => {
    const derived = await fxaCrypto.deriveTokenCredentials(data, token_type);
    return {
      name,
      id: derived.id,
      auth_key: bytesToHex(derived.authKey),
      bundle_key: bytesToHex(derived.bundleKey),
      bearer_header: await fxaCrypto.bearerHeader(data, token_type),
    };
  })
);

results.bundles = await Promise.all(
  job.bundles.map(async ({ name, bundle_key, bundle }) => {
    const { kA, wrapKb } = await fxaCrypto.unbundleKeyFetchResponse(
      hexToBytes(bundle_key),
      bundle
    );
    return { name, ka: bytesToHex(kA), wrap_kb: bytesToHex(wrapKb) };
  })
);

// A bundle whose MAC has been flipped must be rejected, not merely mis-decoded.
results.tampered_bundle_rejected = await (async () => {
  const { bundle_key, bundle } = job.bundles[0];
  const flipped = bundle.slice(0, -1) + (bundle.at(-1) === '0' ? '1' : '0');
  try {
    await fxaCrypto.unbundleKeyFetchResponse(hexToBytes(bundle_key), flipped);
    return false;
  } catch {
    return true;
  }
})();

results.scoped_keys = await Promise.all(
  job.scoped_keys.map(async (entry) => {
    const key = await fxaCrypto.deriveScopedKey({
      scope: entry.scope,
      kb: hexToBytes(entry.kb),
      uid: entry.uid,
      keyRotationSecret: entry.key_rotation_secret,
      keyRotationTimestamp: entry.key_rotation_timestamp,
    });
    return { name: entry.name, k: key.k, kid: key.kid, scope: key.scope, kty: key.kty };
  })
);

results.concat_kdf = b64u(
  await fxaCrypto.concatKdf(
    hexToBytes(job.concat_kdf.shared_secret),
    utf8(job.concat_kdf.algorithm_id),
    utf8(job.concat_kdf.apu),
    utf8(job.concat_kdf.apv),
    job.concat_kdf.key_length
  )
);

const sealed = await fxaCrypto.sealA256Gcm(
  job.a256gcm.protected_b64u,
  hexToBytes(job.a256gcm.cek),
  hexToBytes(job.a256gcm.iv),
  utf8(job.a256gcm.plaintext)
);
results.a256gcm = { ciphertext: b64u(sealed.ciphertext), tag: b64u(sealed.tag) };

// Sealed here, opened by `fxa_lite.crypto.jose` on the Python side: the one
// check that proves the two JWE implementations actually interoperate.
results.jwe = await fxaCrypto.encryptJweEcdhEs(job.jwe.recipient_jwk, utf8(job.jwe.plaintext));

process.stdout.write(JSON.stringify(results));
