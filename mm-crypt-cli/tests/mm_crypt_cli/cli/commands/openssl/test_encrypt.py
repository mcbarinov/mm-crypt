"""Tests for `mm-crypt openssl encrypt`."""

import base64

from click.testing import Result
from mm_crypt_cli.cli.main import app


def _err_text(result: Result) -> str:
    """Return combined stdout + stderr for error-path assertions."""
    return getattr(result, "stderr", "") + result.output


class TestEncryptOutput:
    """Encryption produces a Salted__ ciphertext distinct from the plaintext."""

    def test_base64_has_salted_prefix(self, runner):
        """Base64 mode emits text starting with base64(Salted__)."""
        result = runner.invoke(app, ["openssl", "encrypt", "-p", "pw"], input="hello")
        assert result.exit_code == 0
        assert result.stdout.startswith("U2FsdGVkX1")
        # Sanity: decoded bytes begin with the OpenSSL header.
        assert base64.b64decode("".join(result.stdout.split())).startswith(b"Salted__")

    def test_binary_has_salted_header(self, runner):
        """--binary mode emits raw bytes starting with the Salted__ header."""
        result = runner.invoke(app, ["openssl", "encrypt", "-p", "pw", "--binary"], input=b"hello")
        assert result.exit_code == 0
        assert result.stdout_bytes.startswith(b"Salted__")

    def test_writes_to_output_file_base64(self, runner, tmp_path):
        """--output writes base64 ciphertext to a file."""
        out = tmp_path / "ct.b64"
        result = runner.invoke(app, ["openssl", "encrypt", "-p", "pw", "--output", str(out)], input="hello")
        assert result.exit_code == 0
        assert out.read_text(encoding="utf-8").startswith("U2FsdGVkX1")

    def test_writes_to_output_file_binary(self, runner, tmp_path):
        """--binary with --input / --output reads and writes raw bytes."""
        plain = tmp_path / "plain.bin"
        plain.write_bytes(b"\x00\x01hello\xff")
        out = tmp_path / "ct.bin"
        result = runner.invoke(
            app,
            ["openssl", "encrypt", "-p", "pw", "--binary", "--input", str(plain), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.read_bytes().startswith(b"Salted__")

    def test_reads_from_input_file(self, runner, tmp_path):
        """--input reads plaintext from a file instead of stdin."""
        plain = tmp_path / "plain.txt"
        plain.write_text("hello", encoding="utf-8")
        result = runner.invoke(app, ["openssl", "encrypt", "-p", "pw", "--input", str(plain)])
        assert result.exit_code == 0
        assert result.stdout.startswith("U2FsdGVkX1")


class TestEncryptErrors:
    """Error paths exit with code 1 and a helpful message."""

    def test_missing_password(self, runner):
        """Zero password sources → 'is required'."""
        result = runner.invoke(app, ["openssl", "encrypt"], input="x")
        assert result.exit_code == 1
        assert "is required" in _err_text(result)

    def test_ambiguous_password(self, runner):
        """Two password sources → 'only one of'."""
        result = runner.invoke(app, ["openssl", "encrypt", "-p", "a", "--password-env", "B"], input="x")
        assert result.exit_code == 1
        assert "only one of" in _err_text(result)
