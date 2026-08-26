# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""The browser crypto, pinned to the same vectors as the Python crypto.

`content/assets/crypto.js` does the half of the onepw protocol that runs in the
page: stretching the password, unbundling `kA`/`kB`, deriving scoped keys and
sealing them into `keys_jwe`.  None of it is reachable from pytest, and a
mistake in any of it fails as "Firefox signs in but never syncs" rather than as
an error anyone can read.

So the module is loaded under node — it imports nothing from the DOM — and made
to answer the vectors in `tests/vectors/`, the same ones that pin
`fxa_lite.crypto`.  The last check goes further: the JWE is built in JavaScript
and opened in Python, which is the only way to know the two agree about the
`epk`, the concat KDF and the AAD all at once.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from fxa_lite.crypto import jose
from nodejs import require_node
from vectors import load

DRIVER = Path(__file__).parent / "js" / "crypto_kat.mjs"
MODULE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "fxa_lite"
    / "content"
    / "assets"
    / "crypto.js"
)

JWE_PLAINTEXT = '{"https://identity.mozilla.com/apps/oldsync":{"kty":"oct"}}'


@pytest.fixture(scope="module")
def recipient() -> ec.EllipticCurvePrivateKey:
    """The key the browser would generate and advertise as `keys_jwk`."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def results(recipient: ec.EllipticCurvePrivateKey) -> dict:
    """Run every vector through node once; the tests below just read the answers."""
    node = require_node("the browser crypto cannot be exercised")

    onepw = load("onepw")
    tokens = load("tokens")
    jose_vectors = load("jose")
    job = {
        "credentials": [
            case for case in onepw["credentials"] if case["version"] == 1
        ],
        "derivations": tokens["derivations"],
        "bundles": tokens["account_keys_bundles"],
        "scoped_keys": load("scoped_keys")["keys"],
        "concat_kdf": jose_vectors["ecdh_es"],
        "a256gcm": jose_vectors["a256gcm"],
        "jwe": {
            "recipient_jwk": jose.ec_public_key_to_jwk(recipient.public_key()),
            "plaintext": JWE_PLAINTEXT,
        },
    }
    completed = subprocess.run(
        [node, str(DRIVER), str(MODULE)],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        pytest.fail(f"node driver failed:\n{completed.stderr}")
    return json.loads(completed.stdout)


def test_credentials_match_the_reference(results: dict) -> None:
    expected = [case for case in load("onepw")["credentials"] if case["version"] == 1]
    for got, want in zip(results["credentials"], expected, strict=True):
        assert got["auth_pw"] == want["auth_pw"], want["name"]
        assert got["unwrap_b_key"] == want["unwrap_b_key"], want["name"]


def test_token_derivation_matches_the_reference(results: dict) -> None:
    expected = load("tokens")["derivations"]
    for got, want in zip(results["derivations"], expected, strict=True):
        assert got["id"] == want["id"], want["name"]
        assert got["auth_key"] == want["auth_key"], want["name"]
        assert got["bearer_header"] == want["bearer_header"], want["name"]
        if "bundle_key" in want:
            assert got["bundle_key"] == want["bundle_key"], want["name"]


def test_key_bundle_unwraps_to_the_reference_keys(results: dict) -> None:
    expected = load("tokens")["account_keys_bundles"]
    for got, want in zip(results["bundles"], expected, strict=True):
        assert got["ka"] == want["ka"], want["name"]
        assert got["wrap_kb"] == want["wrap_kb"], want["name"]


def test_a_tampered_bundle_is_rejected(results: dict) -> None:
    # The MAC is the only thing standing between a modified response and a
    # silently wrong `kB`, which would encrypt a user's Sync data under a key
    # nothing can read back.
    assert results["tampered_bundle_rejected"] is True


def test_scoped_keys_match_the_reference(results: dict) -> None:
    expected = load("scoped_keys")["keys"]
    for got, want in zip(results["scoped_keys"], expected, strict=True):
        assert got["k"] == want["k"], want["name"]
        assert got["kid"] == want["kid"], want["name"]
        assert got["kty"] == "oct"
        assert got["scope"] == want["scope"]


def test_concat_kdf_matches_rfc7518_appendix_c(results: dict) -> None:
    assert results["concat_kdf"] == load("jose")["ecdh_es"]["derived_key"]


def test_content_encryption_matches_rfc7516_appendix_a1(results: dict) -> None:
    expected = load("jose")["a256gcm"]
    assert results["a256gcm"]["ciphertext"] == expected["ciphertext"]
    assert results["a256gcm"]["tag"] == expected["tag"]


def test_keys_jwe_built_in_the_browser_opens_in_python(
    results: dict, recipient: ec.EllipticCurvePrivateKey
) -> None:
    """The interop check: JavaScript seals it, Python opens it.

    Nothing else covers the `epk` export, the concat KDF's algorithm binding
    and the protected header used as AAD at the same time — and this is exactly
    what Firefox does with `keys_jwe` when the grant comes back.
    """
    header = json.loads(jose.b64u_decode(results["jwe"].split(".")[0]))
    assert header["alg"] == "ECDH-ES"
    assert header["enc"] == "A256GCM"
    # `exportKey` also hands back `ext` and `key_ops`; neither belongs on the wire.
    assert set(header["epk"]) == {"kty", "crv", "x", "y"}

    assert jose.decrypt_jwe(results["jwe"], recipient) == JWE_PLAINTEXT.encode()
