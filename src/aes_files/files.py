"""File level operations with atomic replacement of the output."""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

from aes_files.header import Header
from aes_files.stream import EncryptionSettings, decrypt_stream, encrypt_stream, read_header


class OutputExistsError(FileExistsError):
    """Raised when the output exists and overwriting was not requested."""


@contextlib.contextmanager
def _atomic_output(path: Path, *, overwrite: bool) -> Iterator[BinaryIO]:
    """Writes to a temporary sibling and renames it only on success, so a
    failed decryption never leaves unauthenticated plaintext behind."""
    if path.exists() and not overwrite:
        raise OutputExistsError(f"{path} already exists, use --force to replace it")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            yield handle
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _process(
    source: Path, target: Path, overwrite: bool, operation: Callable[[BinaryIO, BinaryIO], object]
) -> None:
    with source.open("rb") as reader, _atomic_output(target, overwrite=overwrite) as writer:
        operation(reader, writer)


def encrypt_file(
    source: Path,
    target: Path,
    passphrase: str,
    settings: EncryptionSettings | None = None,
    *,
    overwrite: bool = False,
) -> None:
    _process(
        source,
        target,
        overwrite,
        lambda reader, writer: encrypt_stream(reader, writer, passphrase, settings),
    )


def decrypt_file(source: Path, target: Path, passphrase: str, *, overwrite: bool = False) -> None:
    _process(
        source, target, overwrite, lambda reader, writer: decrypt_stream(reader, writer, passphrase)
    )


def inspect_file(path: Path) -> Header:
    with path.open("rb") as reader:
        return read_header(reader)
