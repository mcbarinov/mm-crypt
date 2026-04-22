"""Tests for `mm-crypt fernet keygen`."""

from mm_crypt_cli.cli.main import app


class TestKeygen:
    """fernet keygen output properties."""

    def test_format(self, runner):
        """Output is a 44-char URL-safe base64 key (32 bytes of entropy)."""
        result = runner.invoke(app, ["fernet", "keygen"])
        assert result.exit_code == 0
        assert len(result.stdout.strip()) == 44

    def test_unique(self, make_key):
        """Successive calls produce distinct keys."""
        keys = {make_key() for _ in range(5)}
        assert len(keys) == 5

    def test_alias(self, runner):
        """`f g` resolves to the same handler as `fernet keygen`."""
        result = runner.invoke(app, ["f", "g"])
        assert result.exit_code == 0
        assert len(result.stdout.strip()) == 44
