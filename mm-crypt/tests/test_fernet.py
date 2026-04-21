"""Tests for mm_crypt.fernet."""

import pytest
from mm_crypt import fernet
from mm_crypt.errors import DecryptionError, InvalidInputError


class TestGenerateKey:
    """Key generation."""

    def test_length(self):
        """Key is 44 chars (URL-safe base64 of 32 bytes)."""
        assert len(fernet.generate_key()) == 44

    def test_unique(self):
        """Each call produces a distinct key."""
        assert len({fernet.generate_key() for _ in range(10)}) == 10

    def test_usable(self):
        """Generated key round-trips encrypt/decrypt."""
        key = fernet.generate_key()
        assert fernet.decrypt(token=fernet.encrypt(data="x", key=key), key=key) == "x"


class TestRoundTrip:
    """Encrypting then decrypting returns the original data."""

    @pytest.mark.parametrize(
        "data",
        [
            "hello world",
            "",
            "a" * 10_000,
            "unicode: привет 🎉 漢字",
            "\n\t\r mixed \x00 bytes",
        ],
    )
    def test_roundtrip(self, data):
        """Plaintext survives an encrypt/decrypt cycle."""
        key = fernet.generate_key()
        assert fernet.decrypt(token=fernet.encrypt(data=data, key=key), key=key) == data


class TestEncrypt:
    """Encryption output properties."""

    def test_token_differs_from_plaintext(self):
        """Token is not the original plaintext."""
        key = fernet.generate_key()
        assert fernet.encrypt(data="hello", key=key) != "hello"

    def test_nondeterministic(self):
        """Same plaintext encrypts to different tokens (fresh IV each call)."""
        key = fernet.generate_key()
        assert fernet.encrypt(data="hello", key=key) != fernet.encrypt(data="hello", key=key)


class TestKnownVector:
    """Regression vector — guards against accidental changes to the algorithm or string encoding."""

    KEY = "OSuBJi_9dBPPuVseU7v3kVmKMqixGmSomq_pEK6VHKg="
    TOKEN = (
        "gAAAAABp50v4kNL6jLMz0DCZ7QiFruUd2xLjt1YsAbCveLPPEdwS2FPooyjEa1B3YL0Csw5N_p9T3VNrjq_jhQDChnu7VzC6cyYjC5MJT7VRU0zs7BJYzUQ="
    )
    PLAINTEXT = "mm-crypt test vector"

    def test_decrypt_static_token(self):
        """Pre-generated token decrypts to the expected plaintext."""
        assert fernet.decrypt(token=self.TOKEN, key=self.KEY) == self.PLAINTEXT

    def test_encrypt_roundtrip_with_static_key(self):
        """Re-encrypting with the static key still round-trips (token itself is non-deterministic)."""
        new_token = fernet.encrypt(data=self.PLAINTEXT, key=self.KEY)
        assert fernet.decrypt(token=new_token, key=self.KEY) == self.PLAINTEXT


class TestDecrypt:
    """Decryption failure modes."""

    def test_wrong_key(self):
        """A token encrypted with one key cannot be decrypted with another."""
        token = fernet.encrypt(data="secret", key=fernet.generate_key())
        with pytest.raises(DecryptionError, match="wrong key or corrupted data"):
            fernet.decrypt(token=token, key=fernet.generate_key())

    def test_malformed_token(self):
        """A garbage string is rejected as a failed decryption (Fernet collapses format and auth)."""
        with pytest.raises(DecryptionError, match="wrong key or corrupted data"):
            fernet.decrypt(token="not-a-real-token", key=fernet.generate_key())

    def test_invalid_key_on_decrypt(self):
        """An ill-formed key raises InvalidInputError before decryption runs."""
        with pytest.raises(InvalidInputError, match="Invalid Fernet key"):
            fernet.decrypt(token="anything", key="not-a-real-key")

    def test_invalid_key_on_encrypt(self):
        """An ill-formed key on encrypt also raises InvalidInputError."""
        with pytest.raises(InvalidInputError, match="Invalid Fernet key"):
            fernet.encrypt(data="anything", key="not-a-real-key")
