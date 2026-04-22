"""Tests for `mm-crypt openssl decrypt`."""

import pytest
from click.testing import Result
from mm_crypt_cli.cli.main import app


def _err_text(result: Result) -> str:
    """Return combined stdout + stderr for error-path assertions."""
    return getattr(result, "stderr", "") + result.output


class TestRoundTrip:
    """encrypt followed by decrypt yields the original payload, via every password source."""

    @pytest.mark.parametrize("binary", [False, True])
    def test_via_password(self, runner, binary):
        """Round-trip via literal -p, in both base64 and --binary modes."""
        payload: str | bytes = b"\x00hello\xff" if binary else "hello"
        mode = ["--binary"] if binary else []
        enc = runner.invoke(app, ["openssl", "encrypt", "-p", "pw", *mode], input=payload)
        assert enc.exit_code == 0
        ct: str | bytes = enc.stdout_bytes if binary else enc.stdout
        dec = runner.invoke(app, ["openssl", "decrypt", "-p", "pw", *mode], input=ct)
        assert dec.exit_code == 0
        got: str | bytes = dec.stdout_bytes if binary else dec.stdout
        assert got == payload

    @pytest.mark.parametrize("binary", [False, True])
    def test_via_password_file(self, runner, tmp_path, binary):
        """Round-trip via --password-file."""
        pwfile = tmp_path / "pw"
        pwfile.write_text("pw", encoding="utf-8")
        payload: str | bytes = b"bytes" if binary else "hello"
        mode = ["--binary"] if binary else []
        enc = runner.invoke(app, ["openssl", "encrypt", "--password-file", str(pwfile), *mode], input=payload)
        assert enc.exit_code == 0
        ct: str | bytes = enc.stdout_bytes if binary else enc.stdout
        dec = runner.invoke(app, ["openssl", "decrypt", "--password-file", str(pwfile), *mode], input=ct)
        assert dec.exit_code == 0
        assert (dec.stdout_bytes if binary else dec.stdout) == payload

    @pytest.mark.parametrize("binary", [False, True])
    def test_via_password_env(self, runner, monkeypatch, binary):
        """Round-trip via --password-env."""
        monkeypatch.setenv("MMC_TEST_OPENSSL_PASSWORD", "pw")
        payload: str | bytes = b"bytes" if binary else "hello"
        mode = ["--binary"] if binary else []
        enc = runner.invoke(
            app,
            ["openssl", "encrypt", "--password-env", "MMC_TEST_OPENSSL_PASSWORD", *mode],
            input=payload,
        )
        assert enc.exit_code == 0
        ct: str | bytes = enc.stdout_bytes if binary else enc.stdout
        dec = runner.invoke(
            app,
            ["openssl", "decrypt", "--password-env", "MMC_TEST_OPENSSL_PASSWORD", *mode],
            input=ct,
        )
        assert dec.exit_code == 0
        assert (dec.stdout_bytes if binary else dec.stdout) == payload

    @pytest.mark.parametrize("binary", [False, True])
    def test_via_files(self, runner, tmp_path, binary):
        """--input / --output route data through files instead of stdin/stdout."""
        if binary:
            plain_data: str | bytes = b"\x00\x01\x02hello\xff"
            plain = tmp_path / "plain.bin"
            plain.write_bytes(plain_data)
            ct_path = tmp_path / "ct.bin"
            out = tmp_path / "out.bin"
        else:
            plain_data = "hello"
            plain = tmp_path / "plain.txt"
            plain.write_text(plain_data, encoding="utf-8")
            ct_path = tmp_path / "ct.b64"
            out = tmp_path / "out.txt"

        mode = ["--binary"] if binary else []
        enc = runner.invoke(
            app,
            ["openssl", "encrypt", "-p", "pw", *mode, "--input", str(plain), "--output", str(ct_path)],
        )
        assert enc.exit_code == 0
        dec = runner.invoke(
            app,
            ["openssl", "decrypt", "-p", "pw", *mode, "--input", str(ct_path), "--output", str(out)],
        )
        assert dec.exit_code == 0
        got: str | bytes = out.read_bytes() if binary else out.read_text(encoding="utf-8")
        assert got == plain_data


class TestAliases:
    """Group and command aliases resolve to the same handlers."""

    def test_group_and_command_aliases(self, runner):
        """`o e` / `o d` route to encrypt/decrypt."""
        enc = runner.invoke(app, ["o", "e", "-p", "pw"], input="aliases")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["o", "d", "-p", "pw"], input=enc.stdout)
        assert dec.exit_code == 0
        assert dec.stdout == "aliases"


class TestDecryptErrors:
    """Decryption-specific error paths exit with code 1 and a helpful message."""

    def test_wrong_password(self, runner):
        """Valid-shape ciphertext with wrong password fails authentication."""
        enc = runner.invoke(app, ["openssl", "encrypt", "-p", "right"], input="payload")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["openssl", "decrypt", "-p", "wrong"], input=enc.stdout)
        assert dec.exit_code == 1
        assert "Decryption failed" in _err_text(dec)

    def test_invalid_base64(self, runner):
        """Garbage that isn't valid base64 is rejected before the cipher runs."""
        result = runner.invoke(app, ["openssl", "decrypt", "-p", "pw"], input="not-base64-!!!")
        assert result.exit_code == 1
        assert "Invalid base64 format" in _err_text(result)

    def test_missing_salt_header(self, runner):
        """Valid base64 whose decoded bytes don't start with Salted__."""
        # base64("hello") decodes fine but lacks the OpenSSL header.
        result = runner.invoke(app, ["openssl", "decrypt", "-p", "pw"], input="aGVsbG8=")
        assert result.exit_code == 1
        assert "missing OpenSSL salt header" in _err_text(result)

    def test_binary_missing_salt_header(self, runner):
        """--binary with raw bytes that don't start with Salted__."""
        result = runner.invoke(app, ["openssl", "decrypt", "-p", "pw", "--binary"], input=b"nothelloatall")
        assert result.exit_code == 1
        assert "missing OpenSSL salt header" in _err_text(result)

    def test_missing_password(self, runner):
        """Decrypt also exercises the resolve_secret missing-password path."""
        result = runner.invoke(app, ["openssl", "decrypt"], input="x")
        assert result.exit_code == 1
        assert "is required" in _err_text(result)

    def test_ambiguous_password(self, runner):
        """Decrypt also exercises the resolve_secret ambiguous path."""
        result = runner.invoke(app, ["openssl", "decrypt", "-p", "a", "--password-env", "B"], input="x")
        assert result.exit_code == 1
        assert "only one of" in _err_text(result)
