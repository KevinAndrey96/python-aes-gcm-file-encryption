import pytest

from aes_files import FormatError, Header, KdfParams
from aes_files.header import HEADER_SIZE, MAGIC

HEADER = Header(KdfParams(), 65536, bytes(range(16)), b"\x01" * 7)


def test_header_round_trip_and_layout() -> None:
    data = HEADER.to_bytes()

    assert len(data) == HEADER_SIZE == 35
    assert data[:5] == MAGIC + b"\x01"
    assert data[5:8] == bytes([17, 8, 1])
    assert Header.from_bytes(data) == HEADER


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"AESF", "too short"),
        (b"ZZZZ" + HEADER.to_bytes()[4:], "not an aes-files container"),
        (MAGIC + b"\x02" + HEADER.to_bytes()[5:], "unsupported format version 2"),
        (HEADER.to_bytes()[:5] + bytes([40, 8, 1]) + HEADER.to_bytes()[8:], "log2"),
    ],
)
def test_rejects_malformed_headers(data: bytes, message: str) -> None:
    with pytest.raises(FormatError, match=message):
        Header.from_bytes(data)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"log2_n": 9}, "log2"),
        ({"r": 0}, "r must be"),
        ({"p": 17}, "p must be"),
    ],
)
def test_kdf_parameters_are_bounded(arguments: dict[str, int], message: str) -> None:
    with pytest.raises(FormatError, match=message):
        KdfParams(**arguments)


def test_header_fields_are_bounded() -> None:
    with pytest.raises(FormatError, match="chunk size"):
        Header(KdfParams(), 8, bytes(16), bytes(7))
    with pytest.raises(FormatError, match="wrong size"):
        Header(KdfParams(), 64, bytes(15), bytes(7))
