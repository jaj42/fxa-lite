"""HKDF-SHA256 against RFC 5869 and the reference server's own vectors."""

import pytest

from fxa_lite.crypto import hkdf
from vectors import cases


def _info(vector: dict) -> bytes:
    return bytes.fromhex(vector["info_hex"]) if "info_hex" in vector else vector["info"].encode()


@pytest.mark.parametrize("vector", cases("hkdf", "raw"), ids=lambda v: v["name"])
def test_raw_hkdf_matches_vector(vector) -> None:
    derived = hkdf.hkdf(
        bytes.fromhex(vector["ikm"]),
        _info(vector),
        bytes.fromhex(vector["salt"]),
        vector["length"],
    )
    assert derived.hex() == vector["expected"]


@pytest.mark.parametrize("vector", cases("hkdf", "namespaced"), ids=lambda v: v["name"])
def test_namespaced_hkdf_matches_vector(vector) -> None:
    derived = hkdf.derive(bytes.fromhex(vector["ikm"]), vector["info"], length=vector["length"])
    assert derived.hex() == vector["expected"]


def test_empty_salt_means_thirty_two_zero_bytes() -> None:
    # RFC 5869 says an absent salt is hashLen zeros; the reference server passes
    # null and relies on the same. Every FxA derivation depends on this.
    assert hkdf.hkdf(b"ikm", b"info") == hkdf.hkdf(b"ikm", b"info", bytes(32))


def test_kw_and_kwe_are_namespaced() -> None:
    assert hkdf.kw("authPW") == b"identity.mozilla.com/picl/v1/authPW"
    assert hkdf.kwe("quickStretch", "a@b.c") == b"identity.mozilla.com/picl/v1/quickStretch:a@b.c"


def test_output_length_is_exact_across_block_boundaries() -> None:
    long = hkdf.hkdf(b"ikm", b"info", length=100)
    assert len(long) == 100
    for length in (1, 32, 33, 64):
        assert hkdf.hkdf(b"ikm", b"info", length=length) == long[:length]


def test_refuses_more_than_hkdf_can_produce() -> None:
    with pytest.raises(ValueError):
        hkdf.hkdf(b"ikm", b"info", length=255 * 32 + 1)
