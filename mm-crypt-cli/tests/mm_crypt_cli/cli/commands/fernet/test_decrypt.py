"""Tests for `mm-crypt fernet decrypt`."""

from mm_crypt_cli.cli.main import app


class TestRoundTrip:
    """encrypt followed by decrypt yields the original plaintext, via every key source."""

    def test_via_key(self, runner, make_key):
        """Round-trip via literal --key."""
        key = make_key()
        enc = runner.invoke(app, ["fernet", "encrypt", "--key", key], input="hello")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key", key], input=enc.stdout)
        assert dec.exit_code == 0
        assert dec.stdout == "hello"

    def test_via_key_file(self, runner, make_key, tmp_path):
        """Round-trip via --key-file."""
        key = make_key()
        keyfile = tmp_path / "k"
        keyfile.write_text(key, encoding="utf-8")
        enc = runner.invoke(app, ["fernet", "encrypt", "--key-file", str(keyfile)], input="hello")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key-file", str(keyfile)], input=enc.stdout)
        assert dec.exit_code == 0
        assert dec.stdout == "hello"

    def test_via_key_env(self, runner, make_key, monkeypatch):
        """Round-trip via --key-env."""
        key = make_key()
        monkeypatch.setenv("MMC_TEST_FERNET_KEY", key)
        enc = runner.invoke(app, ["fernet", "encrypt", "--key-env", "MMC_TEST_FERNET_KEY"], input="hello")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key-env", "MMC_TEST_FERNET_KEY"], input=enc.stdout)
        assert dec.exit_code == 0
        assert dec.stdout == "hello"

    def test_via_files(self, runner, make_key, tmp_path):
        """--input / --output route data through files instead of stdin/stdout."""
        key = make_key()
        plain = tmp_path / "plain.txt"
        plain.write_text("hello", encoding="utf-8")
        token = tmp_path / "token.txt"
        out = tmp_path / "out.txt"
        enc = runner.invoke(app, ["fernet", "encrypt", "--key", key, "--input", str(plain), "--output", str(token)])
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key", key, "--input", str(token), "--output", str(out)])
        assert dec.exit_code == 0
        assert out.read_text(encoding="utf-8") == "hello"

    def test_via_aliases(self, runner, make_key):
        """`f e` / `f d` route to the same handlers as the long form."""
        key = make_key()
        enc = runner.invoke(app, ["f", "e", "--key", key], input="aliases")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["f", "d", "--key", key], input=enc.stdout)
        assert dec.exit_code == 0
        assert dec.stdout == "aliases"


class TestDecryptStripsWhitespace:
    """Regression: decrypt tolerates trailing whitespace appended by editors."""

    def test_trailing_newline(self, runner, make_key):
        """A token with extra trailing newlines still decrypts."""
        key = make_key()
        enc = runner.invoke(app, ["fernet", "encrypt", "--key", key], input="payload")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key", key], input=enc.stdout + "\n\n")
        assert dec.exit_code == 0
        assert dec.stdout == "payload"


class TestDecryptErrors:
    """Decryption-specific error paths."""

    def test_wrong_key(self, runner, make_key, err_text):
        """A valid-shape but wrong key fails authentication, not parsing."""
        key1 = make_key()
        key2 = make_key()
        enc = runner.invoke(app, ["fernet", "encrypt", "--key", key1], input="payload")
        assert enc.exit_code == 0
        dec = runner.invoke(app, ["fernet", "decrypt", "--key", key2], input=enc.stdout)
        assert dec.exit_code == 1
        assert "Decryption failed" in err_text(dec)

    def test_invalid_shape_key(self, runner, err_text):
        """A malformed key on decrypt is rejected before the cipher runs."""
        result = runner.invoke(app, ["fernet", "decrypt", "--key", "not-a-real-key"], input="anything")
        assert result.exit_code == 1
        assert "Invalid Fernet key" in err_text(result)
