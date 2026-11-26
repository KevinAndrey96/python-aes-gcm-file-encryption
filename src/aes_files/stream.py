"""Chunked AES-256-GCM with the STREAM construction (Hoang, Reyhanitabar,
Rogaway and Vizár, 2015).

Chunk i is sealed with nonce = prefix (7 bytes) || i (4 bytes) || last (1
byte), so reordering, dropping or appending chunks, and truncating the file
at a chunk boundary, all fail authentication.
"""

from __future__ import annotations

import io
import os
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from aes_files.header import (
    HEADER_SIZE,
    NONCE_PREFIX_SIZE,
    SALT_SIZE,
    Header,
    KdfParams,
)

KEY_SIZE = 32
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 64 * 1024
MAX_CHUNKS = 1 << 32


class AuthenticationError(ValueError):
    """Raised when the passphrase is wrong or the file was modified."""


@dataclass(frozen=True, slots=True)
class EncryptionSettings:
    params: KdfParams = field(default_factory=KdfParams)
    chunk_size: int = DEFAULT_CHUNK_SIZE


def derive_key(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    """scrypt over the NFC normalized UTF-8 passphrase."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=1 << params.log2_n, r=params.r, p=params.p)

    return kdf.derive(unicodedata.normalize("NFC", passphrase).encode())


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    if index >= MAX_CHUNKS:
        raise ValueError("too many chunks for one file")

    return prefix + index.to_bytes(4, "big") + bytes([last])


def _with_last_flag(source: BinaryIO, size: int) -> Iterator[tuple[bytes, bool]]:
    """Yields fixed size reads, marking the final one (possibly empty)."""
    current = source.read(size)
    while True:
        following = source.read(size)
        if not following:
            yield current, True

            return
        yield current, False
        current = following


def encrypt_stream(
    source: BinaryIO,
    target: BinaryIO,
    passphrase: str,
    settings: EncryptionSettings | None = None,
) -> None:
    settings = settings or EncryptionSettings()
    header = Header(
        settings.params,
        settings.chunk_size,
        os.urandom(SALT_SIZE),
        os.urandom(NONCE_PREFIX_SIZE),
    )
    associated = header.to_bytes()
    cipher = AESGCM(derive_key(passphrase, header.salt, header.params))
    target.write(associated)
    for index, (chunk, last) in enumerate(_with_last_flag(source, header.chunk_size)):
        target.write(cipher.encrypt(_nonce(header.nonce_prefix, index, last), chunk, associated))


def read_header(source: BinaryIO) -> Header:
    return Header.from_bytes(source.read(HEADER_SIZE))


def decrypt_stream(source: BinaryIO, target: BinaryIO, passphrase: str) -> Header:
    """Writes plaintext chunk by chunk; on AuthenticationError the target
    holds a partial result that must be discarded."""
    header = read_header(source)
    associated = header.to_bytes()
    cipher = AESGCM(derive_key(passphrase, header.salt, header.params))
    for index, (chunk, last) in enumerate(_with_last_flag(source, header.chunk_size + TAG_SIZE)):
        try:
            target.write(
                cipher.decrypt(_nonce(header.nonce_prefix, index, last), chunk, associated)
            )
        except InvalidTag as error:
            reason = "wrong passphrase or modified file" if index == 0 else "modified file"
            raise AuthenticationError(f"chunk {index}: {reason}") from error

    return header


def encrypt_bytes(
    data: bytes, passphrase: str, settings: EncryptionSettings | None = None
) -> bytes:
    target = io.BytesIO()
    encrypt_stream(io.BytesIO(data), target, passphrase, settings)

    return target.getvalue()


def decrypt_bytes(data: bytes, passphrase: str) -> bytes:
    target = io.BytesIO()
    decrypt_stream(io.BytesIO(data), target, passphrase)

    return target.getvalue()
