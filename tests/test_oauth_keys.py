"""Loading the signing key, and the retired key that keeps a rotation survivable."""

import json

import pytest

from fxa_lite.cli import write_private_jwk
from fxa_lite.crypto import jose
from fxa_lite.oauth import keys as oauth_keys


@pytest.fixture
def key_file(tmp_path):
    key = jose.generate_signing_key()
    path = tmp_path / "signing-key.json"
    write_private_jwk(path, jose.private_key_to_jwk(key))
    return path


def test_load_reads_the_key_and_builds_a_jwks(key_file) -> None:
    loaded = oauth_keys.load(key_file)
    jwk = json.loads(key_file.read_text())
    assert loaded.kid == jwk["kid"]
    assert loaded.jwks == {"keys": [jose.public_jwk(jwk)]}
    assert list(loaded.verifiers) == [jwk["kid"]]


def test_published_keys_carry_no_private_material(key_file) -> None:
    published = oauth_keys.load(key_file).jwks["keys"][0]
    assert not set(published) & {"d", "p", "q", "dp", "dq", "qi"}


def test_sign_and_verify_round_trip(key_file) -> None:
    loaded = oauth_keys.load(key_file)
    token = loaded.sign({"sub": "abc", "exp": 2**31}, typ="at+JWT")
    assert loaded.verify(token)["sub"] == "abc"


def test_a_token_signed_by_another_key_does_not_verify(key_file, tmp_path) -> None:
    other = tmp_path / "other.json"
    write_private_jwk(other, jose.private_key_to_jwk(jose.generate_signing_key()))
    token = oauth_keys.load(other).sign({"sub": "abc"})
    with pytest.raises(jose.JWTError):
        oauth_keys.load(key_file).verify(token)


def test_a_retired_key_keeps_verifying(key_file, tmp_path) -> None:
    """Rotation must not invalidate a token signed a minute before it."""
    retired_path = tmp_path / "retired.json"
    retired = jose.private_key_to_jwk(jose.generate_signing_key())
    write_private_jwk(retired_path, retired)
    old_token = oauth_keys.load(retired_path).sign({"sub": "abc"})

    # Publish only the public half of the retired key alongside the active one.
    public_retired = tmp_path / "retired-public.json"
    public_retired.write_text(json.dumps(jose.public_jwk(retired)))
    loaded = oauth_keys.load(key_file, public_retired)

    assert len(loaded.jwks["keys"]) == 2
    assert loaded.verify(old_token)["sub"] == "abc"
    # New tokens are still signed by the active key.
    assert jose.decode_jwt_header(loaded.sign({"sub": "abc"}))["kid"] == loaded.kid


def test_a_retired_key_may_not_be_the_active_one(key_file) -> None:
    with pytest.raises(oauth_keys.SigningKeyError):
        oauth_keys.load(key_file, key_file)


def test_a_missing_key_is_an_error_at_load_time(tmp_path) -> None:
    with pytest.raises(oauth_keys.SigningKeyError):
        oauth_keys.load(tmp_path / "absent.json")


def test_a_malformed_key_is_an_error(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(oauth_keys.SigningKeyError):
        oauth_keys.load(path)


def test_a_public_jwk_cannot_be_the_signing_key(key_file, tmp_path) -> None:
    """Only the private half can sign; handing over the public half must fail loudly."""
    path = tmp_path / "public.json"
    path.write_text(json.dumps(jose.public_jwk(json.loads(key_file.read_text()))))
    with pytest.raises(oauth_keys.SigningKeyError):
        oauth_keys.load(path)


def test_the_app_refuses_to_start_without_a_key(tmp_path) -> None:
    """A missing key is a startup failure, not a 500 on the first sign-in."""
    from fxa_lite.app import create_app
    from fxa_lite.config import from_dict

    config = from_dict(
        {"public_url": "http://fxa.example.com", "paths": {"signing_key": "absent.json"}},
        base=tmp_path,
    )
    with pytest.raises(oauth_keys.SigningKeyError):
        create_app(config)
