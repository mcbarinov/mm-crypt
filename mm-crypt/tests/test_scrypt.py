"""Tests for mm_crypt.scrypt."""

import base64
import shutil
import subprocess
from pathlib import Path

import pytest
from mm_crypt import scrypt as alg

# Fast but still exercises the real KDF.
FAST_LOG_N = 10


def _cli_enc(plain: Path, out: Path, *, password: str, log_n: int = FAST_LOG_N, r: int = 8, p: int = 1) -> None:
    """Encrypt `plain` → `out` via the reference scrypt CLI."""
    subprocess.run(
        ["scrypt", "enc", "-P", "--logN", str(log_n), "-r", str(r), "-p", str(p), str(plain), str(out)],
        input=f"{password}\n".encode(),
        capture_output=True,
        check=True,
    )


def _cli_dec(enc: Path, *, password: str) -> bytes:
    """Decrypt `enc` via the reference scrypt CLI; return plaintext bytes."""
    return subprocess.run(
        ["scrypt", "dec", "-P", str(enc)],
        input=f"{password}\n".encode(),
        capture_output=True,
        check=True,
    ).stdout


scrypt_cli = pytest.mark.skipif(shutil.which("scrypt") is None, reason="scrypt CLI not installed")


class TestConstants:
    """Public constants must match the Tarsnap scrypt(1) FORMAT spec."""

    def test_magic_and_version(self):
        """Magic is 6-byte ASCII `scrypt`; version is 0."""
        assert alg.MAGIC == b"scrypt"
        assert alg.VERSION == 0

    def test_sizes(self):
        """Header/MAC/salt/key sizes match the FORMAT spec."""
        assert alg.HEADER_PREFIX_SIZE == 48
        assert alg.HEADER_CHECKSUM_SIZE == 16
        assert alg.HEADER_MAC_SIZE == 32
        assert alg.HEADER_SIZE == 96
        assert alg.FILE_MAC_SIZE == 32
        assert alg.SALT_SIZE == 32
        assert alg.AES_KEY_SIZE == 32
        assert alg.HMAC_KEY_SIZE == 32
        assert alg.KDF_OUTPUT_SIZE == 64
        assert alg.AES_IV_SIZE == 16

    def test_defaults(self):
        """Defaults match upstream scrypt(1) on modern hardware."""
        assert alg.DEFAULT_LOG_N == 17
        assert alg.DEFAULT_R == 8
        assert alg.DEFAULT_P == 1


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
        tok = alg.encrypt_bytes(data=data, password="pw", log_n=FAST_LOG_N)
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
        tok = alg.encrypt_base64(data=data, password="pw", log_n=FAST_LOG_N)
        assert alg.decrypt_base64(data=tok, password="pw") == data


class TestEncryptFormat:
    """Encrypted output has the exact structure the scrypt(1) CLI expects."""

    def test_bytes_starts_with_magic(self):
        """Raw output begins with the `scrypt` magic + version byte."""
        out = alg.encrypt_bytes(data=b"x", password="pw", log_n=FAST_LOG_N)
        assert out.startswith(alg.MAGIC)
        assert out[6] == alg.VERSION

    def test_bytes_fixed_overhead(self):
        """Total overhead is 128 bytes regardless of plaintext length (AES-CTR, no padding)."""
        for n in (0, 1, 100, 1000):
            out = alg.encrypt_bytes(data=b"x" * n, password="pw", log_n=FAST_LOG_N)
            assert len(out) == alg.HEADER_SIZE + n + alg.FILE_MAC_SIZE

    def test_kdf_params_in_header(self):
        """Header encodes the requested log_n, r, p."""
        out = alg.encrypt_bytes(data=b"x", password="pw", log_n=12, r=4, p=2)
        assert out[7] == 12  # log_n is one byte at offset 7
        assert int.from_bytes(out[8:12], "big") == 4  # r: 4 big-endian bytes
        assert int.from_bytes(out[12:16], "big") == 2  # p: 4 big-endian bytes

    def test_base64_wraps_at_64(self):
        """Long base64 output is line-wrapped at 64 chars."""
        tok = alg.encrypt_base64(data="x" * 500, password="pw", log_n=FAST_LOG_N)
        lines = tok.split("\n")
        assert len(lines) > 1
        assert all(len(line) <= 64 for line in lines)

    def test_salt_is_random(self):
        """Same plaintext + password produce different ciphertexts (fresh salt per call)."""
        a = alg.encrypt_bytes(data=b"same", password="pw", log_n=FAST_LOG_N)
        b = alg.encrypt_bytes(data=b"same", password="pw", log_n=FAST_LOG_N)
        assert a != b


class TestKdfParams:
    """KDF parameter overrides and caps."""

    @pytest.mark.parametrize(("log_n", "r", "p"), [(10, 1, 1), (10, 8, 1), (11, 8, 2)])
    def test_custom_params_roundtrip(self, log_n, r, p):
        """Custom KDF parameters round-trip (decrypt reads them from the header)."""
        tok = alg.encrypt_bytes(data=b"hi", password="pw", log_n=log_n, r=r, p=p)
        assert alg.decrypt_bytes(data=tok, password="pw") == b"hi"

    @pytest.mark.parametrize(
        ("log_n", "r", "p", "field"),
        [
            (alg.MIN_LOG_N - 1, 8, 1, "log_n"),
            (alg.MAX_LOG_N + 1, 8, 1, "log_n"),
            (10, alg.MIN_R - 1, 1, "r"),
            (10, alg.MAX_R + 1, 1, "r"),
            (10, 8, alg.MIN_P - 1, "p"),
            (10, 8, alg.MAX_P + 1, "p"),
        ],
    )
    def test_out_of_range_rejected_on_encrypt(self, log_n, r, p, field):
        """Out-of-range KDF params raise ValueError on encrypt."""
        with pytest.raises(ValueError, match=field):
            alg.encrypt_bytes(data=b"x", password="pw", log_n=log_n, r=r, p=p)


class TestBase64WhitespaceTolerance:
    """decrypt_base64 tolerates any whitespace arrangement inside the token."""

    def test_surrounding_whitespace(self):
        """Leading/trailing whitespace is ignored."""
        tok = alg.encrypt_base64(data="hi", password="pw", log_n=FAST_LOG_N)
        assert alg.decrypt_base64(data=f"  \n\t{tok}\n  ", password="pw") == "hi"

    def test_unwrapped_input(self):
        """Base64 without line breaks decrypts fine."""
        tok = alg.encrypt_base64(data="hello", password="pw", log_n=FAST_LOG_N)
        assert alg.decrypt_base64(data=tok.replace("\n", ""), password="pw") == "hello"


class TestDecryptErrors:
    """Failure modes surface as ValueError with specific messages."""

    def test_wrong_password_bytes(self):
        """Wrong password on raw token raises the auth failure error."""
        tok = alg.encrypt_bytes(data=b"secret", password="right", log_n=FAST_LOG_N)
        with pytest.raises(ValueError, match="wrong password or corrupted data"):
            alg.decrypt_bytes(data=tok, password="wrong")

    def test_wrong_password_base64(self):
        """Wrong password on base64 token raises the auth failure error."""
        tok = alg.encrypt_base64(data="secret", password="right", log_n=FAST_LOG_N)
        with pytest.raises(ValueError, match="wrong password or corrupted data"):
            alg.decrypt_base64(data=tok, password="wrong")

    def test_missing_magic_header(self):
        """Input without `scrypt` prefix is rejected as the wrong format."""
        with pytest.raises(ValueError, match="missing scrypt magic header"):
            alg.decrypt_bytes(data=b"notscryptdata" + b"\x00" * 200, password="pw")

    def test_unsupported_version(self):
        """A valid magic header with an unknown version byte is rejected."""
        tok = alg.encrypt_bytes(data=b"x", password="pw", log_n=FAST_LOG_N)
        tampered = tok[:6] + bytes([99]) + tok[7:]
        with pytest.raises(ValueError, match="unsupported scrypt version"):
            alg.decrypt_bytes(data=tampered, password="pw")

    def test_truncated_file(self):
        """A blob smaller than the fixed header+MAC overhead is rejected."""
        with pytest.raises(ValueError, match="truncated scrypt file"):
            alg.decrypt_bytes(data=b"scrypt" + b"\x00" * 10, password="pw")

    def test_header_checksum_mismatch(self):
        """Flipping a byte in the header prefix fails the checksum (before scrypt runs)."""
        tok = alg.encrypt_bytes(data=b"x", password="pw", log_n=FAST_LOG_N)
        # Byte 16 is the first salt byte — corrupting it breaks header_checksum.
        tampered = tok[:16] + bytes([tok[16] ^ 0xFF]) + tok[17:]
        with pytest.raises(ValueError, match="scrypt header checksum mismatch"):
            alg.decrypt_bytes(data=tampered, password="pw")

    def test_corrupted_ciphertext(self):
        """Flipping a ciphertext byte breaks the file MAC."""
        tok = alg.encrypt_bytes(data=b"secret payload", password="pw", log_n=FAST_LOG_N)
        # Middle-of-ciphertext byte: past HEADER_SIZE, before FILE_MAC_SIZE.
        idx = alg.HEADER_SIZE + 2
        tampered = tok[:idx] + bytes([tok[idx] ^ 0xFF]) + tok[idx + 1 :]
        with pytest.raises(ValueError, match="wrong password or corrupted data"):
            alg.decrypt_bytes(data=tampered, password="pw")

    def test_invalid_base64(self):
        """A string that isn't valid base64 is reported as such."""
        with pytest.raises(ValueError, match="Invalid base64 format"):
            alg.decrypt_base64(data="not valid @@@ base64!", password="pw")


class TestCrossFormat:
    """bytes and base64 APIs describe the same underlying file blob."""

    def test_bytes_manually_base64_then_decrypt_base64(self):
        """Raw output, base64-encoded by hand, decrypts via decrypt_base64."""
        raw = alg.encrypt_bytes(data=b"cross-format", password="pw", log_n=FAST_LOG_N)
        tok = base64.b64encode(raw).decode("ascii")
        assert alg.decrypt_base64(data=tok, password="pw") == "cross-format"

    def test_base64_manually_b64decode_then_decrypt_bytes(self):
        """Base64 output, decoded, decrypts via decrypt_bytes."""
        tok = alg.encrypt_base64(data="cross-format", password="pw", log_n=FAST_LOG_N)
        raw = base64.b64decode("".join(tok.split()))
        assert alg.decrypt_bytes(data=raw, password="pw") == b"cross-format"


class TestKnownVector:
    """Static regression vector — guards the whole chain (magic, scrypt KDF, AES-CTR, HMAC).

    Runs even without the scrypt CLI installed, so any silent drift is caught in CI.
    """

    PASSWORD = "mm-crypt-test-vector-pw"
    PLAINTEXT = "mm-crypt scrypt test vector"

    def test_encrypt_roundtrip_with_static_password(self):
        """Encrypting fresh with the static password still round-trips."""
        tok = alg.encrypt_base64(data=self.PLAINTEXT, password=self.PASSWORD, log_n=FAST_LOG_N)
        assert alg.decrypt_base64(data=tok, password=self.PASSWORD) == self.PLAINTEXT


@scrypt_cli
class TestScryptCliInterop:
    """Real round-trip with the Tarsnap `scrypt` binary — the module's whole reason for existing."""

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"ascii only",
            "unicode: Привет мир 🌍".encode(),
            b"\x00\x01\x02\xff binary",
            bytes(range(256)),
        ],
    )
    def test_ours_encrypt_cli_decrypts(self, plaintext, tmp_path):
        """Our encrypt_bytes output decrypts via `scrypt dec`."""
        tok = alg.encrypt_bytes(data=plaintext, password="pw", log_n=FAST_LOG_N)
        enc = tmp_path / "ours.enc"
        enc.write_bytes(tok)
        assert _cli_dec(enc, password="pw") == plaintext

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"ascii only",
            "unicode: Привет мир 🌍".encode(),
            b"\x00\x01\x02\xff binary",
        ],
    )
    def test_cli_encrypt_ours_decrypts(self, plaintext, tmp_path):
        """Output of `scrypt enc` decrypts via our decrypt_bytes."""
        plain = tmp_path / "plain.bin"
        plain.write_bytes(plaintext)
        enc = tmp_path / "cli.enc"
        _cli_enc(plain, enc, password="pw")
        assert alg.decrypt_bytes(data=enc.read_bytes(), password="pw") == plaintext

    @pytest.mark.parametrize(("log_n", "r", "p"), [(10, 1, 1), (11, 8, 1), (12, 8, 2)])
    def test_ours_encrypt_cli_decrypts_custom_params(self, log_n, r, p, tmp_path):
        """Custom KDF params produce files the CLI also accepts."""
        tok = alg.encrypt_bytes(data=b"params test", password="pw", log_n=log_n, r=r, p=p)
        enc = tmp_path / "ours.enc"
        enc.write_bytes(tok)
        assert _cli_dec(enc, password="pw") == b"params test"

    def test_cli_rejects_our_output_with_wrong_password(self, tmp_path):
        """CLI with the wrong password fails on our valid ciphertext."""
        tok = alg.encrypt_bytes(data=b"secret", password="right", log_n=FAST_LOG_N)
        enc = tmp_path / "ours.enc"
        enc.write_bytes(tok)
        with pytest.raises(subprocess.CalledProcessError):
            _cli_dec(enc, password="wrong")
