"""Single-owner binary container formats (.sdv).

SDV3: magic (AAD) | nonce | AES-GCM(metadata length | metadata | file bytes).
SDV1: magic | metadata length | metadata | nonce | AES-GCM(file bytes).
The SDV1 header through the metadata is AAD. All lengths are uint32 big-endian.
"""
import struct
from dataclasses import dataclass

from vault.crypto_core import NONCE_SIZE_BYTES, TAG_SIZE_BYTES
from vault.exceptions import ContainerFormatError

MAGIC = b"SDV1"
PRIVATE_MAGIC = b"SDV3"
LENGTH_FORMAT = ">I"                     # unsigned 32-bit, big-endian
LENGTH_SIZE = struct.calcsize(LENGTH_FORMAT)
MAX_METADATA_SIZE = 64 * 1024            # refuse absurd lengths before allocating
FILE_EXTENSION = ".sdv"


@dataclass(frozen=True)
class Container:
    header: bytes             # raw header bytes used as AAD
    metadata_bytes: bytes | None  # present in legacy SDV1 only
    nonce: bytes
    ciphertext_with_tag: bytes


def build_header(metadata_bytes: bytes) -> bytes:
    """Return the legacy SDV1 header."""
    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise ContainerFormatError("Metadata too large")
    return MAGIC + struct.pack(LENGTH_FORMAT, len(metadata_bytes)) + metadata_bytes


def pack(metadata_bytes: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Concatenate the parts of a legacy SDV1 container."""
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ContainerFormatError("Invalid nonce length")
    return build_header(metadata_bytes) + nonce + ciphertext_with_tag


def pack_private_payload(metadata_bytes: bytes, plaintext: bytes) -> bytes:
    """Build the plaintext that will be encrypted inside SDV3."""
    if not 0 < len(metadata_bytes) <= MAX_METADATA_SIZE:
        raise ContainerFormatError("Invalid metadata length")
    return struct.pack(LENGTH_FORMAT, len(metadata_bytes)) + metadata_bytes + plaintext


def unpack_private_payload(payload: bytes) -> tuple[bytes, bytes]:
    """Split authenticated SDV3 plaintext into metadata and file bytes."""
    if len(payload) < LENGTH_SIZE:
        raise ContainerFormatError("Missing metadata length")
    (meta_len,) = struct.unpack_from(LENGTH_FORMAT, payload)
    end = LENGTH_SIZE + meta_len
    if not 0 < meta_len <= MAX_METADATA_SIZE or end > len(payload):
        raise ContainerFormatError("Invalid metadata length")
    return payload[LENGTH_SIZE:end], payload[end:]


def pack_private(nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Wrap encrypted SDV3 plaintext without exposing metadata."""
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ContainerFormatError("Invalid nonce length")
    if len(ciphertext_with_tag) < LENGTH_SIZE + TAG_SIZE_BYTES:
        raise ContainerFormatError("Container truncated")
    return PRIVATE_MAGIC + nonce + ciphertext_with_tag


def unpack(data: bytes) -> Container:
    """Split a container into its parts using fixed offsets.

    This only checks the *structure*. Nothing extracted here is trusted
    until the AEAD tag has been verified.
    """
    if data.startswith(PRIVATE_MAGIC):
        nonce_end = len(PRIVATE_MAGIC) + NONCE_SIZE_BYTES
        if len(data) < nonce_end + LENGTH_SIZE + TAG_SIZE_BYTES:
            raise ContainerFormatError("Container truncated")
        return Container(
            header=PRIVATE_MAGIC,
            metadata_bytes=None,
            nonce=data[len(PRIVATE_MAGIC):nonce_end],
            ciphertext_with_tag=data[nonce_end:],
        )

    min_size = len(MAGIC) + LENGTH_SIZE + NONCE_SIZE_BYTES + TAG_SIZE_BYTES
    if len(data) < min_size:
        raise ContainerFormatError("Container too short")

    if data[:len(MAGIC)] != MAGIC:
        raise ContainerFormatError("Not a vault container (bad magic)")

    offset = len(MAGIC)
    (meta_len,) = struct.unpack(LENGTH_FORMAT, data[offset:offset + LENGTH_SIZE])
    offset += LENGTH_SIZE

    if meta_len > MAX_METADATA_SIZE:
        raise ContainerFormatError("Declared metadata length too large")
    if len(data) < offset + meta_len + NONCE_SIZE_BYTES + TAG_SIZE_BYTES:
        raise ContainerFormatError("Container truncated")

    metadata_bytes = data[offset:offset + meta_len]
    offset += meta_len
    header = data[:offset]

    nonce = data[offset:offset + NONCE_SIZE_BYTES]
    offset += NONCE_SIZE_BYTES

    return Container(
        header=header,
        metadata_bytes=metadata_bytes,
        nonce=nonce,
        ciphertext_with_tag=data[offset:],
    )
