"""Tests for mm_crypt.openssl_aes256cbc."""

import base64
import shutil
import subprocess

import pytest
from mm_crypt import openssl_aes256cbc as alg
from mm_crypt.errors import DecryptionError, InvalidInputError


def _cli_args(*extra: str, password: str) -> list[str]:
    """Build an `openssl enc` command with the algorithm/iter params this module targets."""
    return [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        str(alg.ITERATIONS),
        *extra,
        "-pass",
        f"pass:{password}",
    ]


def _cli_run(args: list[str], stdin: bytes) -> bytes:
    """Run a CLI command with stdin bytes; return stdout bytes. Raises on non-zero exit."""
    return subprocess.run(args, input=stdin, capture_output=True, check=True).stdout


def openssl_encrypt_base64(data: bytes, password: str) -> str:
    """Encrypt via CLI, output base64."""
    return _cli_run(_cli_args("-salt", "-base64", password=password), data).decode("ascii")


def openssl_decrypt_base64(token: str, password: str) -> bytes:
    """Decrypt base64 token via CLI. OpenSSL 3.x requires a trailing newline on base64 stdin."""
    stdin = token.encode("ascii")
    if not stdin.endswith(b"\n"):
        stdin += b"\n"
    return _cli_run(_cli_args("-d", "-base64", password=password), stdin)


def openssl_encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt via CLI, output raw bytes (no -base64)."""
    return _cli_run(_cli_args("-salt", password=password), data)


def openssl_decrypt_bytes(data: bytes, password: str) -> bytes:
    """Decrypt raw bytes via CLI (no -base64)."""
    return _cli_run(_cli_args("-d", password=password), data)


openssl_cli = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl CLI not installed",
)


class TestConstants:
    """Public constants must match the OpenSSL enc format used by the CLI."""

    def test_magic_header(self):
        """Magic is the 8-byte literal `Salted__`."""
        assert alg.MAGIC_HEADER == b"Salted__"

    def test_sizes(self):
        """Salt / key / block sizes match AES-256-CBC with OpenSSL's 8-byte salt."""
        assert (alg.SALT_SIZE, alg.KEY_SIZE, alg.BLOCK_SIZE) == (8, 32, 16)

    def test_iterations(self):
        """PBKDF2 iteration count matches the `-iter` value the CLI needs."""
        assert alg.ITERATIONS == 1_000_000


class TestRoundTripBytes:
    """encrypt_bytes / decrypt_bytes are inverses."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"hello",
            bytes(range(256)),
            b"A" * 10_000,
            "unicode bytes: Привет 🎉".encode(),
        ],
    )
    def test_roundtrip(self, data):
        """Raw bytes survive encrypt/decrypt."""
        tok = alg.encrypt_bytes(data=data, password="pw")
        assert alg.decrypt_bytes(data=tok, password="pw") == data


class TestRoundTripBase64:
    """encrypt_base64 / decrypt_base64 are inverses."""

    @pytest.mark.parametrize(
        "data",
        [
            "",
            "hello world",
            "unicode: Привет мир 🌍 こんにちは",
            "multiline\nwith\ttabs\r\n",
            "x" * 10_000,
        ],
    )
    def test_roundtrip(self, data):
        """Strings survive encrypt/decrypt."""
        tok = alg.encrypt_base64(data=data, password="pw")
        assert alg.decrypt_base64(data=tok, password="pw") == data


class TestEncryptFormat:
    """Encrypted output has the exact structure OpenSSL expects."""

    def test_bytes_starts_with_magic(self):
        """Raw output begins with the `Salted__` magic header."""
        out = alg.encrypt_bytes(data=b"x", password="pw")
        assert out.startswith(alg.MAGIC_HEADER)

    def test_bytes_layout(self):
        """Layout is: 8-byte magic + 8-byte salt + AES-block-aligned ciphertext."""
        out = alg.encrypt_bytes(data=b"x", password="pw")
        ciphertext = out[len(alg.MAGIC_HEADER) + alg.SALT_SIZE :]
        assert len(ciphertext) > 0
        assert len(ciphertext) % alg.BLOCK_SIZE == 0

    def test_base64_wraps_at_64(self):
        """Long base64 output is line-wrapped at 64 chars (matches `openssl -base64`)."""
        tok = alg.encrypt_base64(data="x" * 500, password="pw")
        lines = tok.split("\n")
        assert len(lines) > 1
        assert all(len(line) <= 64 for line in lines)

    def test_salt_is_random(self):
        """Same plaintext + password produce different ciphertexts (fresh salt each call)."""
        assert alg.encrypt_bytes(data=b"same", password="pw") != alg.encrypt_bytes(data=b"same", password="pw")


class TestBase64WhitespaceTolerance:
    """decrypt_base64 tolerates any whitespace arrangement inside the token."""

    def test_surrounding_whitespace(self):
        """Leading/trailing whitespace is ignored."""
        tok = alg.encrypt_base64(data="hi", password="pw")
        assert alg.decrypt_base64(data=f"  \n\t{tok}\n  ", password="pw") == "hi"

    def test_unwrapped_input(self):
        """Base64 without line breaks decrypts fine."""
        tok = alg.encrypt_base64(data="hello", password="pw")
        assert alg.decrypt_base64(data=tok.replace("\n", ""), password="pw") == "hello"


class TestDecryptErrors:
    """Failure modes surface as typed errors with specific messages."""

    def test_wrong_password_bytes(self):
        """Wrong password on raw token raises DecryptionError."""
        tok = alg.encrypt_bytes(data=b"secret", password="right")
        with pytest.raises(DecryptionError, match="wrong password or corrupted data"):
            alg.decrypt_bytes(data=tok, password="wrong")

    def test_wrong_password_base64(self):
        """Wrong password on base64 token raises DecryptionError."""
        tok = alg.encrypt_base64(data="secret", password="right")
        with pytest.raises(DecryptionError, match="wrong password or corrupted data"):
            alg.decrypt_base64(data=tok, password="wrong")

    def test_missing_magic_header_bytes(self):
        """Raw input without `Salted__` prefix is rejected as InvalidInputError."""
        with pytest.raises(InvalidInputError, match="missing OpenSSL salt header"):
            alg.decrypt_bytes(data=b"not-an-openssl-file", password="pw")

    def test_missing_magic_header_base64(self):
        """Valid base64 decoding to non-OpenSSL bytes is rejected as InvalidInputError."""
        bogus = base64.b64encode(b"not-an-openssl-file").decode("ascii")
        with pytest.raises(InvalidInputError, match="missing OpenSSL salt header"):
            alg.decrypt_base64(data=bogus, password="pw")

    def test_truncated(self):
        """Only the magic header, no salt or ciphertext — unpad fails with DecryptionError."""
        with pytest.raises(DecryptionError, match="wrong password or corrupted data"):
            alg.decrypt_bytes(data=alg.MAGIC_HEADER, password="pw")

    def test_corrupted_ciphertext(self):
        """Flipping the last ciphertext byte breaks decryption."""
        tok = alg.encrypt_bytes(data=b"secret", password="pw")
        corrupted = tok[:-1] + bytes([tok[-1] ^ 0xFF])
        with pytest.raises(DecryptionError, match="wrong password or corrupted data"):
            alg.decrypt_bytes(data=corrupted, password="pw")

    def test_invalid_base64(self):
        """A string that isn't valid base64 is reported as InvalidInputError."""
        with pytest.raises(InvalidInputError, match="Invalid base64 format"):
            alg.decrypt_base64(data="not valid @@@ base64!", password="pw")


class TestCrossFormat:
    """bytes and base64 APIs describe the same underlying ciphertext."""

    def test_bytes_manually_base64_then_decrypt_base64(self):
        """Raw output, base64-encoded by hand, decrypts via decrypt_base64."""
        raw = alg.encrypt_bytes(data=b"cross-format", password="pw")
        tok = base64.b64encode(raw).decode("ascii")
        assert alg.decrypt_base64(data=tok, password="pw") == "cross-format"

    def test_base64_manually_b64decode_then_decrypt_bytes(self):
        """Base64 output, decoded, decrypts via decrypt_bytes."""
        tok = alg.encrypt_base64(data="cross-format", password="pw")
        raw = base64.b64decode("".join(tok.split()))
        assert alg.decrypt_bytes(data=raw, password="pw") == b"cross-format"


class TestKnownVector:
    """Static regression vector — guards the whole chain (magic, PBKDF2, AES, PKCS7, base64).

    Runs even without the openssl CLI installed, so any silent drift in defaults is caught in CI.
    """

    PASSWORD = "mm-crypt-test-vector-pw"
    PLAINTEXT = "mm-crypt openssl_aes256cbc test vector"
    BASE64_TOKEN = "U2FsdGVkX19rK2G3+jkixUWuHhkeC1iR4UBv0h+bH4ydsS8yCbFV4+e2XlUX0tyF\nOGLyTZukMY4Kg0X9kNK2vA=="
    BYTES_TOKEN_HEX = (
        "53616c7465645f5f77a926d251a545ce2f00df098f87e8956f292fe37c52c1f3"
        "20ad02fa9d8566b056d52cfbbc2b2f578077d5db2f66728f2daadc1fe4efee24"
    )

    def test_decrypt_base64_static(self):
        """Pre-generated base64 token decrypts to the expected plaintext."""
        assert alg.decrypt_base64(data=self.BASE64_TOKEN, password=self.PASSWORD) == self.PLAINTEXT

    def test_decrypt_bytes_static(self):
        """Pre-generated raw token decrypts to the expected plaintext."""
        raw = bytes.fromhex(self.BYTES_TOKEN_HEX)
        assert alg.decrypt_bytes(data=raw, password=self.PASSWORD).decode("utf-8") == self.PLAINTEXT

    def test_encrypt_roundtrip_with_static_password(self):
        """Encrypting fresh with the static password still round-trips (ciphertext is non-deterministic)."""
        tok = alg.encrypt_base64(data=self.PLAINTEXT, password=self.PASSWORD)
        assert alg.decrypt_base64(data=tok, password=self.PASSWORD) == self.PLAINTEXT


@openssl_cli
class TestOpensslCliInterop:
    """Real round-trip with the `openssl` binary — the module's whole reason for existing."""

    @pytest.mark.parametrize(
        "plaintext",
        [
            "ascii only",
            "unicode: Привет мир 🌍 こんにちは",
            "special: !@#$%^&*()[]{}|<>?",
        ],
    )
    def test_ours_encrypt_base64_cli_decrypts(self, plaintext):
        """Our base64 output decrypts via `openssl enc -d -base64`."""
        tok = alg.encrypt_base64(data=plaintext, password="pw")
        assert openssl_decrypt_base64(tok, "pw").decode("utf-8") == plaintext

    def test_ours_encrypt_base64_wrapped_cli_decrypts(self):
        """Wrapped base64 (multi-line) still decrypts via the CLI."""
        plaintext = "x" * 500
        tok = alg.encrypt_base64(data=plaintext, password="pw")
        assert "\n" in tok
        assert openssl_decrypt_base64(tok, "pw").decode("utf-8") == plaintext

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"ascii only",
            "unicode: Привет мир 🌍".encode(),
            b"\x00\x01\x02\xff binary",
            bytes(range(256)),
        ],
    )
    def test_ours_encrypt_bytes_cli_decrypts(self, plaintext):
        """Our raw output decrypts via `openssl enc -d` (no -base64)."""
        tok = alg.encrypt_bytes(data=plaintext, password="pw")
        assert openssl_decrypt_bytes(tok, "pw") == plaintext

    @pytest.mark.parametrize(
        "plaintext",
        [
            "ascii only",
            "unicode: Привет мир 🌍 こんにちは",
        ],
    )
    def test_cli_encrypt_base64_ours_decrypts(self, plaintext):
        """Output of `openssl enc -base64` decrypts via our decrypt_base64."""
        tok = openssl_encrypt_base64(plaintext.encode("utf-8"), "pw")
        assert alg.decrypt_base64(data=tok, password="pw") == plaintext

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"ascii only",
            b"\x00\x01\x02\xff binary",
            bytes(range(256)),
        ],
    )
    def test_cli_encrypt_bytes_ours_decrypts(self, plaintext):
        """Output of `openssl enc` (no -base64) decrypts via our decrypt_bytes."""
        raw = openssl_encrypt_bytes(plaintext, "pw")
        assert alg.decrypt_bytes(data=raw, password="pw") == plaintext

    def test_cli_rejects_our_output_with_wrong_password(self):
        """CLI with the wrong password fails on our valid ciphertext (symmetric security)."""
        tok = alg.encrypt_base64(data="secret", password="right")
        with pytest.raises(subprocess.CalledProcessError):
            openssl_decrypt_base64(tok, "wrong")
