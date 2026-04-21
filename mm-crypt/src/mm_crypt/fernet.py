"""Fernet symmetric encryption — thin functional wrapper over `cryptography.fernet.Fernet`."""

from cryptography.fernet import Fernet


def generate_key() -> str:
    """Generate a new Fernet key (URL-safe base64-encoded, 32 bytes of entropy)."""
    return Fernet.generate_key().decode()


def encrypt(*, data: str, key: str) -> str:
    """Encrypt a UTF-8 string with the given Fernet key; return the token as str."""
    return Fernet(key).encrypt(data.encode()).decode()


def decrypt(*, token: str, key: str) -> str:
    """Decrypt a Fernet token with the given key; return the original UTF-8 string."""
    return Fernet(key).decrypt(token).decode()
