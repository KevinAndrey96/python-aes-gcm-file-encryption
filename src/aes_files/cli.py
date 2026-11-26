"""Command line interface: encrypt, decrypt and inspect files.

The passphrase never travels in argv (visible in process listings and shell
history): it comes from AES_FILES_PASSPHRASE or an interactive prompt.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from aes_files.files import decrypt_file, encrypt_file, inspect_file
from aes_files.header import FormatError, KdfParams
from aes_files.stream import DEFAULT_CHUNK_SIZE, AuthenticationError, EncryptionSettings

PASSPHRASE_VARIABLE = "AES_FILES_PASSPHRASE"


class PassphraseError(ValueError):
    """Raised when no usable passphrase was provided."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aes-files", description="Cifrado autenticado de archivos con AES-256-GCM."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    encrypter = commands.add_parser("encrypt", help="cifrar un archivo")
    decrypter = commands.add_parser("decrypt", help="descifrar un archivo")
    for command in (encrypter, decrypter):
        command.add_argument("source", type=Path)
        command.add_argument("target", type=Path)
        command.add_argument("--force", action="store_true", help="reemplazar el destino")
    encrypter.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    encrypter.add_argument("--scrypt-log2-n", type=int, default=KdfParams().log2_n)
    inspector = commands.add_parser("inspect", help="mostrar la cabecera de un archivo cifrado")
    inspector.add_argument("source", type=Path)

    return parser


def _passphrase(confirm: bool) -> str:
    value = os.environ.get(PASSPHRASE_VARIABLE)
    if value is None:
        value = getpass.getpass("Frase de paso: ")
        if confirm and getpass.getpass("Repita la frase de paso: ") != value:
            raise PassphraseError("passphrases do not match")
    if not value:
        raise PassphraseError("passphrase must not be empty")

    return value


def _run(arguments: argparse.Namespace, target: TextIO) -> None:
    if arguments.command == "inspect":
        header = inspect_file(arguments.source)
        target.write(
            f"formato: AESF v1\nscrypt: N=2^{header.params.log2_n} r={header.params.r} "
            f"p={header.params.p}\nbloque: {header.chunk_size} bytes\nsal: {header.salt.hex()}\n"
        )
    elif arguments.command == "encrypt":
        encrypt_file(
            arguments.source,
            arguments.target,
            _passphrase(confirm=True),
            EncryptionSettings(KdfParams(log2_n=arguments.scrypt_log2_n), arguments.chunk_size),
            overwrite=arguments.force,
        )
        target.write(f"cifrado: {arguments.target}\n")
    else:
        decrypt_file(
            arguments.source,
            arguments.target,
            _passphrase(confirm=False),
            overwrite=arguments.force,
        )
        target.write(f"descifrado: {arguments.target}\n")


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        _run(arguments, stdout or sys.stdout)
    except (AuthenticationError, FormatError, PassphraseError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)

        return 2

    return 0
