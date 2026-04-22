"""Tests for `mm-crypt fernet encrypt`."""

from mm_crypt_cli.cli.main import app


class TestEncryptOutput:
    """Encryption produces a non-empty token distinct from the plaintext."""

    def test_token_differs_from_plaintext(self, runner, make_key):
        """The emitted token is not the original plaintext."""
        key = make_key()
        result = runner.invoke(app, ["fernet", "encrypt", "--key", key], input="hello")
        assert result.exit_code == 0
        assert result.stdout != "hello"
        assert result.stdout.startswith("gAAAAA")  # Fernet token prefix

    def test_writes_to_output_file(self, runner, make_key, tmp_path):
        """--output writes the token to the given path instead of stdout."""
        key = make_key()
        out = tmp_path / "token.txt"
        result = runner.invoke(app, ["fernet", "encrypt", "--key", key, "--output", str(out)], input="hello")
        assert result.exit_code == 0
        assert out.read_text(encoding="utf-8").startswith("gAAAAA")

    def test_reads_from_input_file(self, runner, make_key, tmp_path):
        """--input reads plaintext from a file instead of stdin."""
        key = make_key()
        plain = tmp_path / "plain.txt"
        plain.write_text("hello", encoding="utf-8")
        result = runner.invoke(app, ["fernet", "encrypt", "--key", key, "--input", str(plain)])
        assert result.exit_code == 0
        assert result.stdout.startswith("gAAAAA")


class TestEncryptErrors:
    """Error paths exit with code 1 and a helpful message."""

    def test_missing_key(self, runner, err_text):
        """Zero key sources → 'is required'."""
        result = runner.invoke(app, ["fernet", "encrypt"], input="x")
        assert result.exit_code == 1
        assert "is required" in err_text(result)

    def test_ambiguous_key(self, runner, err_text):
        """Two key sources → 'only one of'."""
        result = runner.invoke(app, ["fernet", "encrypt", "--key", "a", "--key-env", "B"], input="x")
        assert result.exit_code == 1
        assert "only one of" in err_text(result)

    def test_empty_key(self, runner, err_text):
        """Empty --key '' → 'is empty'."""
        result = runner.invoke(app, ["fernet", "encrypt", "--key", ""], input="x")
        assert result.exit_code == 1
        assert "is empty" in err_text(result)

    def test_invalid_shape_key(self, runner, err_text):
        """A malformed key string is rejected before reaching the cipher."""
        result = runner.invoke(app, ["fernet", "encrypt", "--key", "not-a-real-key"], input="x")
        assert result.exit_code == 1
        assert "Invalid Fernet key" in err_text(result)
