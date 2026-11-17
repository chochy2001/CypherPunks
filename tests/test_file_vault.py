"""End-to-end tests on real files (the five tests required by D2)."""
import json
import os
import struct
from pathlib import Path

import pytest

from vault import container, crypto_core, file_vault
from vault.exceptions import ContainerFormatError, IntegrityError, VaultError

PDF_LIKE = b"%PDF-1.7\n" + os.urandom(4096) + b"\n%%EOF\n"


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "contract.pdf"
    path.write_bytes(PDF_LIKE)
    return path


@pytest.fixture
def legacy_package(sample, tmp_path):
    metadata = crypto_core.build_metadata(sample.name, timestamp=1_700_000_000)
    metadata_bytes = crypto_core.canonicalize_metadata(metadata)
    header = b"SDV1" + struct.pack(">I", len(metadata_bytes)) + metadata_bytes
    key = crypto_core.generate_key()
    nonce, ciphertext_with_tag = crypto_core.encrypt(key, sample.read_bytes(), header)
    path = tmp_path / "legacy.sdv"
    path.write_bytes(header + nonce + ciphertext_with_tag)
    return path, key


def tamper(path, index):
    data = bytearray(path.read_bytes())
    data[index] ^= 0x01
    path.write_bytes(bytes(data))


# 1. Encrypt -> decrypt returns identical file
def test_encrypt_decrypt_identical_file(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    restored = file_vault.decrypt_file(sdv, key, output_dir=str(out_dir))
    assert os.path.basename(restored) == "contract.pdf"
    assert open(restored, "rb").read() == PDF_LIKE


def test_container_does_not_contain_plaintext_or_key(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    data = open(sdv, "rb").read()
    assert PDF_LIKE[:64] not in data
    assert key not in data


def test_private_container_hides_and_restores_original_name(tmp_path):
    source = tmp_path / "synthetic-confidential-document-9243.bin"
    source.write_bytes(b"synthetic fixture payload")
    sdv, key = file_vault.encrypt_file(str(source), str(tmp_path / "package.sdv"))
    data = Path(sdv).read_bytes()

    assert source.name.encode() not in data
    assert data.startswith(b"SDV3")

    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    restored = file_vault.decrypt_file(sdv, key, output_dir=str(restored_dir))
    assert Path(restored) == restored_dir / source.name
    assert Path(restored).read_bytes() == source.read_bytes()


def test_legacy_container_restores_original_name(legacy_package, tmp_path):
    sdv, key = legacy_package
    out_dir = tmp_path / "restored"
    out_dir.mkdir()

    restored = file_vault.decrypt_file(str(sdv), key, output_dir=str(out_dir))
    assert Path(restored) == out_dir / "contract.pdf"
    assert Path(restored).read_bytes() == PDF_LIKE


def test_private_container_restores_empty_file_and_unicode_name(tmp_path):
    source = tmp_path / "café.txt"
    source.touch()
    sdv, key = file_vault.encrypt_file(str(source))
    source.unlink()

    assert Path(sdv).name == "café.txt.sdv"
    assert Path(file_vault.decrypt_file(sdv, key)) == source
    assert source.read_bytes() == b""


# 2. Wrong key fails
def test_wrong_key_fails(sample, tmp_path):
    sdv, _ = file_vault.encrypt_file(str(sample))
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, crypto_core.generate_key(),
                                output_path=str(tmp_path / "x.pdf"))


# 3. Modified ciphertext fails
def test_modified_ciphertext_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    tamper(Path(sdv), -100)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


# 4. Modified metadata fails
def test_modified_metadata_fails(legacy_package, tmp_path):
    sdv, key = legacy_package
    data = sdv.read_bytes()
    # Rename the file inside the metadata, keeping the same length.
    tampered = data.replace(b"contract.pdf", b"contrakt.pdf")
    assert tampered != data
    sdv.write_bytes(tampered)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(str(sdv), key, output_path=str(tmp_path / "x.pdf"))


def test_modified_timestamp_fails(legacy_package, tmp_path):
    sdv, key = legacy_package
    parts = container.unpack(sdv.read_bytes())
    meta = json.loads(parts.metadata_bytes)
    meta["timestamp"] += 1
    new_meta = crypto_core.canonicalize_metadata(meta)
    forged = container.pack(new_meta, parts.nonce, parts.ciphertext_with_tag)
    sdv.write_bytes(forged)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(str(sdv), key, output_path=str(tmp_path / "x.pdf"))


def test_modified_private_metadata_ciphertext_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    metadata_offset = len(b"SDV3") + crypto_core.NONCE_SIZE_BYTES + 4
    tamper(Path(sdv), metadata_offset)

    target = tmp_path / "should-not-exist.pdf"
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(target))
    assert not target.exists()


@pytest.mark.parametrize(
    "declared_length, metadata_bytes",
    [(0, b""), (2**32 - 1, b"{}"), (10, b"{}"), (3, b"???")],
)
def test_malformed_private_metadata_writes_nothing(
    declared_length, metadata_bytes, tmp_path,
):
    payload = struct.pack(">I", declared_length) + metadata_bytes
    key = crypto_core.generate_key()
    nonce, ciphertext_with_tag = crypto_core.encrypt(key, payload, b"SDV3")
    sdv = tmp_path / "invalid.sdv"
    sdv.write_bytes(b"SDV3" + nonce + ciphertext_with_tag)

    target = tmp_path / "should-not-exist.pdf"
    with pytest.raises(ContainerFormatError):
        file_vault.decrypt_file(str(sdv), key, output_path=str(target))
    assert not target.exists()


def test_modified_nonce_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    parts = container.unpack(open(sdv, "rb").read())
    tamper(Path(sdv), len(parts.header))   # first nonce byte
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


def test_modified_magic_fails(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    tamper(Path(sdv), 0)
    with pytest.raises(ContainerFormatError):
        file_vault.decrypt_file(sdv, key)


# 5. Multiple encryptions produce different ciphertexts
def test_two_encryptions_differ(sample, tmp_path):
    a, key_a = file_vault.encrypt_file(str(sample), str(tmp_path / "a.sdv"))
    b, key_b = file_vault.encrypt_file(str(sample), str(tmp_path / "b.sdv"))
    pa = container.unpack(open(a, "rb").read())
    pb = container.unpack(open(b, "rb").read())
    assert key_a != key_b
    assert pa.nonce != pb.nonce
    assert pa.ciphertext_with_tag != pb.ciphertext_with_tag


# Safe failure
def test_failed_decryption_writes_nothing(sample, tmp_path):
    sdv, _ = file_vault.encrypt_file(str(sample))
    target = tmp_path / "should_not_exist.pdf"
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, crypto_core.generate_key(), output_path=str(target))
    assert not target.exists()
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".vault-tmp-")]


def test_decrypt_does_not_overwrite_existing_file(sample):
    # Default output is the original name in the same folder: the original.
    sdv, key = file_vault.encrypt_file(str(sample))
    sample.write_bytes(b"newer local version")
    with pytest.raises(VaultError):
        file_vault.decrypt_file(sdv, key)
    assert sample.read_bytes() == b"newer local version"


def test_decrypt_overwrite_when_requested(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    sample.write_bytes(b"newer local version")
    file_vault.decrypt_file(sdv, key, overwrite=True)
    assert sample.read_bytes() == PDF_LIKE
