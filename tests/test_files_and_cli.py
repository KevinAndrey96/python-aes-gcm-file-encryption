import io
import subprocess
import sys
from pathlib import Path

import pytest

from aes_files import (
    AuthenticationError,
    EncryptionSettings,
    OutputExistsError,
    decrypt_file,
    encrypt_file,
    inspect_file,
)
from aes_files.cli import main

from .conftest import FAST

SECRET = b"informe trimestral\n" * 50


@pytest.fixture
def plain(tmp_path: Path) -> Path:
    path = tmp_path / "informe.txt"
    path.write_bytes(SECRET)

    return path


def test_file_round_trip(plain: Path, tmp_path: Path) -> None:
    sealed, opened = tmp_path / "informe.aesf", tmp_path / "copia.txt"
    encrypt_file(plain, sealed, "pw", FAST)
    decrypt_file(sealed, opened, "pw")

    assert opened.read_bytes() == SECRET
    assert inspect_file(sealed).chunk_size == 64


def test_refuses_to_overwrite_without_permission(plain: Path, tmp_path: Path) -> None:
    sealed = tmp_path / "informe.aesf"
    encrypt_file(plain, sealed, "pw", FAST)

    with pytest.raises(OutputExistsError, match="use --force"):
        encrypt_file(plain, sealed, "pw", FAST)
    encrypt_file(plain, plain, "pw", FAST, overwrite=True)
    decrypt_file(plain, plain, "pw", overwrite=True)
    assert plain.read_bytes() == SECRET


def test_failed_decryption_leaves_no_output(plain: Path, tmp_path: Path) -> None:
    sealed, opened = tmp_path / "informe.aesf", tmp_path / "copia.txt"
    encrypt_file(plain, sealed, "pw", FAST)
    sealed.write_bytes(sealed.read_bytes()[:-1])

    with pytest.raises(AuthenticationError):
        decrypt_file(sealed, opened, "pw")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["informe.aesf", "informe.txt"]


def run(argv: list[str]) -> tuple[int, str]:
    output = io.StringIO()

    return main(argv, stdout=output), output.getvalue()


def test_cli_with_environment_passphrase(
    plain: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AES_FILES_PASSPHRASE", "pw")
    sealed, opened = tmp_path / "s.aesf", tmp_path / "o.txt"

    assert run(["encrypt", str(plain), str(sealed), "--scrypt-log2-n", "10"]) == (
        0,
        f"cifrado: {sealed}\n",
    )
    assert run(["decrypt", str(sealed), str(opened)]) == (0, f"descifrado: {opened}\n")
    assert opened.read_bytes() == SECRET
    status, report = run(["inspect", str(sealed)])
    assert status == 0
    assert "scrypt: N=2^10 r=8 p=1" in report
    assert "bloque: 65536 bytes" in report


def test_cli_prompts_and_confirms(
    plain: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AES_FILES_PASSPHRASE", raising=False)
    answers = iter(["pw", "pw", "pw"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))
    sealed, opened = tmp_path / "s.aesf", tmp_path / "o.txt"

    assert run(["encrypt", str(plain), str(sealed), "--scrypt-log2-n", "10"])[0] == 0
    assert run(["decrypt", str(sealed), str(opened)])[0] == 0
    assert opened.read_bytes() == SECRET


@pytest.mark.parametrize(
    ("answers", "message"),
    [(["a", "b"], "do not match"), (["", ""], "must not be empty")],
)
def test_cli_rejects_bad_passphrases(
    answers: list[str],
    message: str,
    plain: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("AES_FILES_PASSPHRASE", raising=False)
    replies = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(replies))

    assert run(["encrypt", str(plain), str(plain.parent / "s.aesf")]) == (2, "")
    assert message in capsys.readouterr().err


def test_cli_reports_errors(
    plain: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AES_FILES_PASSPHRASE", "pw")

    assert run(["decrypt", str(plain), str(tmp_path / "o")]) == (2, "")
    assert run(["inspect", str(tmp_path / "missing")]) == (2, "")
    assert capsys.readouterr().err.count("error:") == 2


def test_module_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "aes_files", "--help"], capture_output=True, text=True, check=True
    )

    assert "AES-256-GCM" in completed.stdout
    assert EncryptionSettings().params.log2_n == 17
