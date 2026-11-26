import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aes_files import (
    AuthenticationError,
    EncryptionSettings,
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
)
from aes_files.header import HEADER_SIZE, KdfParams
from aes_files.stream import TAG_SIZE, _nonce

from .conftest import FAST

SEALED = 64 + TAG_SIZE


@given(st.binary(max_size=600))
@settings(deadline=None, max_examples=40)
def test_round_trip(data: bytes) -> None:
    assert decrypt_bytes(encrypt_bytes(data, "correct horse", FAST), "correct horse") == data


@pytest.mark.parametrize(("size", "chunks"), [(0, 1), (1, 1), (64, 1), (65, 2), (128, 2)])
def test_output_size(size: int, chunks: int) -> None:
    sealed = encrypt_bytes(b"a" * size, "pw", FAST)

    assert len(sealed) == HEADER_SIZE + size + chunks * TAG_SIZE


def test_same_input_never_encrypts_the_same() -> None:
    assert encrypt_bytes(b"secret", "pw", FAST) != encrypt_bytes(b"secret", "pw", FAST)


def test_wrong_passphrase() -> None:
    sealed = encrypt_bytes(b"secret", "pw", FAST)

    with pytest.raises(AuthenticationError, match="chunk 0: wrong passphrase or modified file"):
        decrypt_bytes(sealed, "PW")


def test_passphrase_is_unicode_normalized() -> None:
    sealed = encrypt_bytes(b"secret", "contrase\u00f1a", FAST)

    assert decrypt_bytes(sealed, "contrasen\u0303a") == b"secret"


def test_detects_a_flipped_bit_anywhere() -> None:
    sealed = bytearray(encrypt_bytes(b"x" * 200, "pw", FAST))
    for position in (6, 20, HEADER_SIZE, HEADER_SIZE + SEALED + 3, len(sealed) - 1):
        tampered = bytearray(sealed)
        tampered[position] ^= 1
        with pytest.raises((AuthenticationError, ValueError)):
            decrypt_bytes(bytes(tampered), "pw")


def test_detects_truncation_at_a_chunk_boundary() -> None:
    sealed = encrypt_bytes(b"x" * 200, "pw", FAST)

    with pytest.raises(AuthenticationError, match="chunk 1: modified file"):
        decrypt_bytes(sealed[: HEADER_SIZE + 2 * SEALED], "pw")
    with pytest.raises(AuthenticationError, match="chunk 0"):
        decrypt_bytes(sealed[:HEADER_SIZE], "pw")


def test_detects_reordered_chunks() -> None:
    sealed = encrypt_bytes(b"a" * 64 + b"b" * 64 + b"c" * 10, "pw", FAST)
    body = sealed[HEADER_SIZE:]
    swapped = sealed[:HEADER_SIZE] + body[SEALED : 2 * SEALED] + body[:SEALED] + body[2 * SEALED :]

    with pytest.raises(AuthenticationError, match="chunk 0"):
        decrypt_bytes(swapped, "pw")


def test_derive_key_rejects_empty_passphrases() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        derive_key("", bytes(16), KdfParams(log2_n=10))


def test_nonce_layout_and_chunk_limit() -> None:
    assert _nonce(b"P" * 7, 1, last=True) == b"PPPPPPP\x00\x00\x00\x01\x01"
    with pytest.raises(ValueError, match="too many chunks"):
        _nonce(b"P" * 7, 1 << 32, last=False)


def test_default_settings_round_trip() -> None:
    sealed = encrypt_bytes(b"default", "pw")

    assert sealed[5] == 17
    assert decrypt_bytes(sealed, "pw") == b"default"
    assert EncryptionSettings().chunk_size == 65536
