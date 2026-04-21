"""Fernet symmetric encryption — thin functional wrapper over `cryptography.fernet.Fernet`."""

from cryptography.fernet import Fernet, InvalidToken

from mm_crypt.errors import DecryptionError, InvalidInputError


def generate_key() -> str:
    """Generate a new Fernet key (URL-safe base64-encoded, 32 bytes of entropy)."""
    return Fernet.generate_key().decode()


def encrypt(*, data: str, key: str) -> str:
    """Encrypt a UTF-8 string with the given Fernet key; return the token as str.

    Raises:
        InvalidInputError: `key` is not a valid Fernet key.

    """
    try:
        cipher = Fernet(key)
    except ValueError as exc:
        raise InvalidInputError("Invalid Fernet key") from exc
    return cipher.encrypt(data.encode()).decode()


def decrypt(*, token: str, key: str) -> str:
    """Decrypt a Fernet token with the given key; return the original UTF-8 string.

    Raises:
        InvalidInputError: `key` is not a valid Fernet key.
        DecryptionError: the token could not be authenticated. Note: Fernet does not
            distinguish "wrong key" from "malformed token" — both surface as this
            error, so a completely bogus `token` string also raises DecryptionError
            (not InvalidInputError).

    """
    try:
        cipher = Fernet(key)
    except ValueError as exc:
        raise InvalidInputError("Invalid Fernet key") from exc
    try:
        return cipher.decrypt(token).decode()
    except InvalidToken as exc:
        raise DecryptionError("Decryption failed: wrong key or corrupted data") from exc
