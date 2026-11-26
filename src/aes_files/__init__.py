"""Authenticated file encryption with chunked AES-256-GCM and scrypt."""

from aes_files.files import OutputExistsError, decrypt_file, encrypt_file, inspect_file
from aes_files.header import FormatError, Header, KdfParams
from aes_files.stream import (
    AuthenticationError,
    EncryptionSettings,
    decrypt_bytes,
    decrypt_stream,
    derive_key,
    encrypt_bytes,
    encrypt_stream,
)

__all__ = [
    "AuthenticationError",
    "EncryptionSettings",
    "FormatError",
    "Header",
    "KdfParams",
    "OutputExistsError",
    "decrypt_bytes",
    "decrypt_file",
    "decrypt_stream",
    "derive_key",
    "encrypt_bytes",
    "encrypt_file",
    "encrypt_stream",
    "inspect_file",
]
