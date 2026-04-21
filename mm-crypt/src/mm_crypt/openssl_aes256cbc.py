"""AES-256-CBC encryption compatible with `openssl enc -aes-256-cbc -pbkdf2 -iter 1000000`.

Data encrypted by this module can be decrypted by the OpenSSL CLI binary, and vice versa.
Format: `Salted__` magic header (8 bytes) + 8-byte salt + AES-256-CBC ciphertext with PKCS7 padding.
Key/IV derived via PBKDF2-HMAC-SHA256 with 1,000,000 iterations.

CLI round-trip examples:
    echo "secret" | openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -base64 -pass pass:pw
    echo "<token>" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -base64 -pass pass:pw
"""

import base64
import binascii
import secrets
import textwrap
from hashlib import pbkdf2_hmac

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mm_crypt.errors import DecryptionError, InvalidInputError

MAGIC_HEADER: bytes = b"Salted__"  # OpenSSL's fixed preamble marking a salted file
SALT_SIZE: int = 8  # OpenSSL's salt length
KEY_SIZE: int = 32  # AES-256 key length
BLOCK_SIZE: int = 16  # AES block size (also CBC IV size)
ITERATIONS: int = 1_000_000  # PBKDF2 iteration count; must match the `-iter` value on the CLI side


def _derive_key_iv(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive (key, IV) from password and salt via PBKDF2-HMAC-SHA256."""
    material = pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=ITERATIONS,
        dklen=KEY_SIZE + BLOCK_SIZE,
    )
    return material[:KEY_SIZE], material[KEY_SIZE:]


def encrypt_bytes(*, data: bytes, password: str) -> bytes:
    """Encrypt raw bytes; return `Salted__` + salt + ciphertext (OpenSSL-compatible)."""
    salt = secrets.token_bytes(SALT_SIZE)
    key, iv = _derive_key_iv(password, salt)

    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded = padder.update(data) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return MAGIC_HEADER + salt + ciphertext


def decrypt_bytes(*, data: bytes, password: str) -> bytes:
    """Decrypt OpenSSL-format bytes (as produced by `encrypt_bytes`).

    Raises:
        InvalidInputError: `data` does not start with the OpenSSL `Salted__` magic header.
        DecryptionError: wrong password or the ciphertext was tampered with.

    """
    if not data.startswith(MAGIC_HEADER):
        raise InvalidInputError("Invalid format: missing OpenSSL salt header")

    header_len = len(MAGIC_HEADER)
    salt = data[header_len : header_len + SALT_SIZE]
    ciphertext = data[header_len + SALT_SIZE :]

    key, iv = _derive_key_iv(password, salt)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()

    try:
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise DecryptionError("Decryption failed: wrong password or corrupted data") from exc


def encrypt_base64(*, data: str, password: str) -> str:
    """Encrypt a UTF-8 string; return base64 wrapped at 64 chars (matches `openssl -base64` output)."""
    raw = encrypt_bytes(data=data.encode("utf-8"), password=password)
    return textwrap.fill(base64.b64encode(raw).decode("ascii"), width=64)


def decrypt_base64(*, data: str, password: str) -> str:
    """Decode base64 (whitespace tolerated) and decrypt to a UTF-8 string.

    Raises:
        InvalidInputError: `data` isn't valid base64, or the decoded blob lacks the OpenSSL header.
        DecryptionError: wrong password or the ciphertext was tampered with.

    """
    try:
        raw = base64.b64decode("".join(data.split()))
    except binascii.Error as exc:
        raise InvalidInputError("Invalid base64 format") from exc
    return decrypt_bytes(data=raw, password=password).decode("utf-8")
