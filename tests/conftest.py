import pytest

from aes_files import EncryptionSettings, KdfParams

FAST = EncryptionSettings(KdfParams(log2_n=10), chunk_size=64)


@pytest.fixture
def fast() -> EncryptionSettings:
    return FAST
