"""Tests for `mm-crypt scrypt encrypt`."""

import base64

from click.testing import Result
from mm_crypt_cli.cli.main import app

# Minimum log_n keeps every scrypt call under ~1 ms / ~1 MiB RAM so the suite stays cheap under xdist.
_FAST = ["-N", "10"]


def _err_text(result: Result) -> str:
    """Return combined stdout + stderr for error-path assertions."""
    return getattr(result, "stderr", "") + result.output


class TestEncryptOutput:
    """Encryption produces a scrypt-format blob routed through the requested sink."""

    def test_base64_has_scrypt_magic(self, runner):
        """Base64 mode emits text that decodes to bytes starting with `scrypt`."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", *_FAST], input="hello")
        assert result.exit_code == 0
        assert base64.b64decode("".join(result.stdout.split())).startswith(b"scrypt")

    def test_binary_has_scrypt_magic(self, runner):
        """--binary mode emits raw bytes starting with the `scrypt` magic."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", "--binary", *_FAST], input=b"hello")
        assert result.exit_code == 0
        assert result.stdout_bytes.startswith(b"scrypt")

    def test_writes_to_output_file_base64(self, runner, tmp_path):
        """--output writes base64 ciphertext to a file."""
        out = tmp_path / "ct.b64"
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", *_FAST, "--output", str(out)], input="hello")
        assert result.exit_code == 0
        assert base64.b64decode("".join(out.read_text(encoding="utf-8").split())).startswith(b"scrypt")

    def test_writes_to_output_file_binary(self, runner, tmp_path):
        """--binary with --input / --output reads and writes raw bytes."""
        plain = tmp_path / "plain.bin"
        plain.write_bytes(b"\x00\x01hello\xff")
        out = tmp_path / "ct.bin"
        result = runner.invoke(
            app,
            ["scrypt", "encrypt", "-p", "pw", "--binary", *_FAST, "--input", str(plain), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.read_bytes().startswith(b"scrypt")

    def test_reads_from_input_file(self, runner, tmp_path):
        """--input reads plaintext from a file instead of stdin."""
        plain = tmp_path / "plain.txt"
        plain.write_text("hello", encoding="utf-8")
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", *_FAST, "--input", str(plain)])
        assert result.exit_code == 0
        assert base64.b64decode("".join(result.stdout.split())).startswith(b"scrypt")


class TestKdfParams:
    """-N / --r / --p flags must actually flow into the cipher call."""

    def test_kdf_params_persisted_in_header(self, runner):
        """Custom -N / --r / --p values land in the encrypted file's header."""
        result = runner.invoke(
            app, ["scrypt", "encrypt", "-p", "pw", "--binary", "-N", "12", "--r", "4", "--p", "2"], input=b"hello"
        )
        assert result.exit_code == 0
        # Header layout (per Tarsnap scrypt FORMAT): magic(6) + version(1) + log_n(1) + r(4, BE) + p(4, BE).
        header = result.stdout_bytes[:16]
        assert header[:6] == b"scrypt"
        assert header[7] == 12
        assert int.from_bytes(header[8:12], "big") == 4
        assert int.from_bytes(header[12:16], "big") == 2

    def test_log_n_out_of_range(self, runner):
        """-N below the library's minimum surfaces InvalidInputError as a CliError."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", "-N", "5"], input="hello")
        assert result.exit_code == 1
        assert "log_n must be in" in _err_text(result)

    def test_r_out_of_range(self, runner):
        """--r above the library's maximum surfaces InvalidInputError as a CliError."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", "--r", "100"], input="hello")
        assert result.exit_code == 1
        assert "r must be in" in _err_text(result)

    def test_p_out_of_range(self, runner):
        """--p above the library's maximum surfaces InvalidInputError as a CliError."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "pw", "--p", "100"], input="hello")
        assert result.exit_code == 1
        assert "p must be in" in _err_text(result)


class TestEncryptErrors:
    """Error paths exit with code 1 and a helpful message."""

    def test_missing_password(self, runner):
        """Zero password sources → 'is required'."""
        result = runner.invoke(app, ["scrypt", "encrypt"], input="x")
        assert result.exit_code == 1
        assert "is required" in _err_text(result)

    def test_ambiguous_password(self, runner):
        """Two password sources → 'only one of'."""
        result = runner.invoke(app, ["scrypt", "encrypt", "-p", "a", "--password-env", "B"], input="x")
        assert result.exit_code == 1
        assert "only one of" in _err_text(result)
