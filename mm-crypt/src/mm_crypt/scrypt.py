"""scrypt encryption compatible with Tarsnap's `scrypt(1)` file format.

Data encrypted by this module can be decrypted by the third-party `scrypt` CLI,
and vice versa. The binary file layout follows the upstream FORMAT document:
https://github.com/Tarsnap/scrypt/blob/master/FORMAT

Primitives:
- KDF: scrypt (RFC 7914) — memory-hard, resistant to GPU/ASIC attacks
- Cipher: AES-256-CTR (single 64-byte scrypt output split into AES key + HMAC key)
- Authentication: HMAC-SHA-256 over header, and over header || ciphertext
- All-zero AES IV is safe: the salt is fresh per encryption, so the AES key is unique per file

CLI round-trip examples (interactive passphrase prompt):
    scrypt enc plain.txt cipher.enc
    scrypt dec cipher.enc plain.txt

Non-interactive form (reads passphrase from stdin, first line):
    echo "$PASSWORD" | scrypt enc -P plain.txt cipher.enc
    echo "$PASSWORD" | scrypt dec -P cipher.enc plain.txt

Install the reference CLI: `brew install scrypt` / `apt install scrypt` / `pacman -S scrypt`.
Source: https://github.com/Tarsnap/scrypt
"""

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import textwrap

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from mm_crypt.errors import DecryptionError, InvalidInputError

MAGIC: bytes = b"scrypt"  # 6-byte file signature
VERSION: int = 0  # Current (and only) format version

# Field sizes (bytes).
HEADER_PREFIX_SIZE: int = 48  # magic(6) + version(1) + log_n(1) + r(4) + p(4) + salt(32)
HEADER_CHECKSUM_SIZE: int = 16  # First 16 bytes of SHA-256(header_prefix)
HEADER_MAC_SIZE: int = 32  # HMAC-SHA-256(hmac_key, header_prefix || header_checksum)
HEADER_SIZE: int = HEADER_PREFIX_SIZE + HEADER_CHECKSUM_SIZE + HEADER_MAC_SIZE  # = 96
FILE_MAC_SIZE: int = 32  # HMAC-SHA-256(hmac_key, everything before it)
SALT_SIZE: int = 32  # scrypt salt
AES_KEY_SIZE: int = 32  # AES-256
HMAC_KEY_SIZE: int = 32  # HMAC-SHA-256 key
KDF_OUTPUT_SIZE: int = AES_KEY_SIZE + HMAC_KEY_SIZE  # 64 bytes from one scrypt call
AES_IV_SIZE: int = 16  # All-zero IV — safe because salt is unique per file → key is unique

# Default scrypt work factor (matches upstream scrypt(1) defaults on modern hardware).
DEFAULT_LOG_N: int = 17  # N = 2^17 = 131072; ~100 ms, ~128 MiB on a modern CPU
DEFAULT_R: int = 8
DEFAULT_P: int = 1

# Sanity caps on KDF params. Enforced on both encrypt and decrypt so a hostile
# file cannot force a scrypt memory bomb, and honest input gets a clear error.
MIN_LOG_N: int = 10
MAX_LOG_N: int = 20
MIN_R: int = 1
MAX_R: int = 32
MIN_P: int = 1
MAX_P: int = 16

# Header layout: 6-byte magic, version byte, log_n byte, 32-bit r, 32-bit p, 32-byte salt.
_HEADER_PREFIX_STRUCT = struct.Struct(">6sBBII32s")


def encrypt_bytes(
    *,
    data: bytes,
    password: str,
    log_n: int = DEFAULT_LOG_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
) -> bytes:
    """Encrypt raw bytes; return a scrypt(1)-format blob (header + ciphertext + MAC).

    Raises:
        InvalidInputError: `log_n`, `r`, or `p` is outside the supported range.

    """
    _check_kdf_params(log_n, r, p)
    salt = secrets.token_bytes(SALT_SIZE)
    header_prefix = _HEADER_PREFIX_STRUCT.pack(MAGIC, VERSION, log_n, r, p, salt)
    aes_key, hmac_key = _derive_keys(password, salt, log_n, r, p)

    header_checksum = hashlib.sha256(header_prefix).digest()[:HEADER_CHECKSUM_SIZE]
    header_mac = hmac.new(hmac_key, header_prefix + header_checksum, hashlib.sha256).digest()
    header = header_prefix + header_checksum + header_mac

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b"\x00" * AES_IV_SIZE)).encryptor()
    ciphertext = cipher.update(data) + cipher.finalize()

    file_mac = hmac.new(hmac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + file_mac


def decrypt_bytes(*, data: bytes, password: str) -> bytes:
    """Decrypt a scrypt(1)-format blob (as produced by `encrypt_bytes` or `scrypt enc`).

    Raises:
        InvalidInputError: `data` is truncated, lacks the scrypt magic header, has an
            unsupported version, or fails the header checksum.
        DecryptionError: wrong password or the file has been tampered with.

    """
    if len(data) < HEADER_SIZE + FILE_MAC_SIZE:
        raise InvalidInputError("Invalid format: truncated scrypt file")

    header_prefix = data[:HEADER_PREFIX_SIZE]
    header_checksum = data[HEADER_PREFIX_SIZE : HEADER_PREFIX_SIZE + HEADER_CHECKSUM_SIZE]
    header_mac = data[HEADER_PREFIX_SIZE + HEADER_CHECKSUM_SIZE : HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:-FILE_MAC_SIZE]
    file_mac = data[-FILE_MAC_SIZE:]

    magic, version, log_n, r, p, salt = _HEADER_PREFIX_STRUCT.unpack(header_prefix)
    if magic != MAGIC:
        raise InvalidInputError("Invalid format: missing scrypt magic header")
    if version != VERSION:
        raise InvalidInputError(f"Invalid format: unsupported scrypt version {version}")

    # Cheap integrity check — catches random corruption without running scrypt.
    expected_checksum = hashlib.sha256(header_prefix).digest()[:HEADER_CHECKSUM_SIZE]
    if not hmac.compare_digest(expected_checksum, header_checksum):
        raise InvalidInputError("Invalid format: scrypt header checksum mismatch")

    # KDF params + scrypt + MACs share one error path: wrong password, tampering,
    # and out-of-range KDF params all collapse into the same failure.
    try:
        _check_kdf_params(log_n, r, p)
        aes_key, hmac_key = _derive_keys(password, salt, log_n, r, p)
    except (InvalidInputError, ValueError, MemoryError, OverflowError) as exc:
        raise DecryptionError("Decryption failed: wrong password or corrupted data") from exc

    expected_header_mac = hmac.new(hmac_key, header_prefix + header_checksum, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_header_mac, header_mac):
        raise DecryptionError("Decryption failed: wrong password or corrupted data")

    expected_file_mac = hmac.new(hmac_key, data[:-FILE_MAC_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(expected_file_mac, file_mac):
        raise DecryptionError("Decryption failed: wrong password or corrupted data")

    # Authenticate-before-decrypt: AES runs only after both MACs pass.
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b"\x00" * AES_IV_SIZE)).decryptor()
    return cipher.update(ciphertext) + cipher.finalize()


def encrypt_base64(
    *,
    data: str,
    password: str,
    log_n: int = DEFAULT_LOG_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
) -> str:
    """Encrypt a UTF-8 string; return base64 wrapped at 64 chars.

    Raises:
        InvalidInputError: `log_n`, `r`, or `p` is outside the supported range.

    """
    raw = encrypt_bytes(data=data.encode("utf-8"), password=password, log_n=log_n, r=r, p=p)
    return textwrap.fill(base64.b64encode(raw).decode("ascii"), width=64)


def decrypt_base64(*, data: str, password: str) -> str:
    """Decode base64 (whitespace tolerated) and decrypt to a UTF-8 string.

    Raises:
        InvalidInputError: `data` isn't valid base64, or the decoded blob is malformed
            (truncated, wrong magic, unsupported version, bad header checksum).
        DecryptionError: wrong password or the file has been tampered with.

    """
    try:
        raw = base64.b64decode("".join(data.split()))
    except binascii.Error as exc:
        raise InvalidInputError("Invalid base64 format") from exc
    return decrypt_bytes(data=raw, password=password).decode("utf-8")


def _derive_keys(password: str, salt: bytes, log_n: int, r: int, p: int) -> tuple[bytes, bytes]:
    """One scrypt call → 64 bytes → (AES-256 key, HMAC-SHA-256 key)."""
    material = Scrypt(salt=salt, length=KDF_OUTPUT_SIZE, n=1 << log_n, r=r, p=p).derive(password.encode("utf-8"))
    return material[:AES_KEY_SIZE], material[AES_KEY_SIZE:]


def _check_kdf_params(log_n: int, r: int, p: int) -> None:
    """Reject KDF params outside the documented caps."""
    if not MIN_LOG_N <= log_n <= MAX_LOG_N:
        raise InvalidInputError(f"log_n must be in [{MIN_LOG_N}, {MAX_LOG_N}]: got {log_n}")
    if not MIN_R <= r <= MAX_R:
        raise InvalidInputError(f"r must be in [{MIN_R}, {MAX_R}]: got {r}")
    if not MIN_P <= p <= MAX_P:
        raise InvalidInputError(f"p must be in [{MIN_P}, {MAX_P}]: got {p}")
