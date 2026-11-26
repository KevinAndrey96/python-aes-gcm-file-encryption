"""Binary header of an encrypted file.

    offset  size  field
    0       4     magic "AESF"
    4       1     format version (1)
    5       1     scrypt log2(N)
    6       1     scrypt r
    7       1     scrypt p
    8       4     plaintext chunk size, big endian
    12      16    scrypt salt
    28      7     nonce prefix

The whole header is authenticated as associated data of every chunk.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"AESF"
VERSION = 1
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 7
_LAYOUT = struct.Struct(f">4sBBBBI{SALT_SIZE}s{NONCE_PREFIX_SIZE}s")
HEADER_SIZE = _LAYOUT.size

MIN_LOG2_N = 10
MAX_LOG2_N = 22
MIN_CHUNK_SIZE = 16
MAX_CHUNK_SIZE = 1 << 24


class FormatError(ValueError):
    """Raised when a file is not in the expected format."""


@dataclass(frozen=True, slots=True)
class KdfParams:
    """scrypt cost; the default (N = 2^17, r = 8, p = 1) uses 128 MiB of memory."""

    log2_n: int = 17
    r: int = 8
    p: int = 1

    def __post_init__(self) -> None:
        if not MIN_LOG2_N <= self.log2_n <= MAX_LOG2_N:
            raise FormatError(f"scrypt log2(N) must be between {MIN_LOG2_N} and {MAX_LOG2_N}")
        if not (1 <= self.r <= 32 and 1 <= self.p <= 16):
            raise FormatError("scrypt r must be 1-32 and p must be 1-16")


@dataclass(frozen=True, slots=True)
class Header:
    params: KdfParams
    chunk_size: int
    salt: bytes
    nonce_prefix: bytes

    def __post_init__(self) -> None:
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise FormatError(f"chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}")
        if len(self.salt) != SALT_SIZE or len(self.nonce_prefix) != NONCE_PREFIX_SIZE:
            raise FormatError("salt or nonce prefix has the wrong size")

    def to_bytes(self) -> bytes:
        return _LAYOUT.pack(
            MAGIC,
            VERSION,
            self.params.log2_n,
            self.params.r,
            self.params.p,
            self.chunk_size,
            self.salt,
            self.nonce_prefix,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Header:
        if len(data) < HEADER_SIZE:
            raise FormatError("file is too short to hold a header")
        magic, version, log2_n, r, p, chunk_size, salt, prefix = _LAYOUT.unpack(data[:HEADER_SIZE])
        if magic != MAGIC:
            raise FormatError("not an aes-files container")
        if version != VERSION:
            raise FormatError(f"unsupported format version {version}")

        return cls(KdfParams(log2_n, r, p), chunk_size, salt, prefix)
