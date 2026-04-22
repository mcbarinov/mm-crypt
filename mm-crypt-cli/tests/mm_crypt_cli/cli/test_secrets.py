"""Tests for mm_crypt_cli.cli.secrets.resolve_secret."""

import pytest
from mm_clikit import CliError
from mm_crypt_cli.cli.secrets import resolve_secret

FLAGS = ("--key", "--key-file", "--key-env")
LABEL = "Fernet key"


class TestSourceResolution:
    """Each of the three sources resolves to its value."""

    def test_value(self):
        """Literal --key value is returned as-is."""
        assert resolve_secret(value="abc", file=None, env=None, flags=FLAGS, label=LABEL) == "abc"

    def test_file(self, tmp_path):
        """--key-file content is returned, with surrounding whitespace stripped."""
        f = tmp_path / "k"
        f.write_text("abc\n", encoding="utf-8")
        assert resolve_secret(value=None, file=f, env=None, flags=FLAGS, label=LABEL) == "abc"

    def test_file_strips_inner_padding(self, tmp_path):
        """Leading/trailing whitespace is stripped; inner content is not touched."""
        f = tmp_path / "k"
        f.write_text("  abc def  \n\n", encoding="utf-8")
        assert resolve_secret(value=None, file=f, env=None, flags=FLAGS, label=LABEL) == "abc def"

    def test_env(self, monkeypatch):
        """--key-env value is read from os.environ."""
        monkeypatch.setenv("MMC_TEST_SECRET", "abc")
        assert resolve_secret(value=None, file=None, env="MMC_TEST_SECRET", flags=FLAGS, label=LABEL) == "abc"


class TestSourceCount:
    """Exactly one source must be supplied."""

    def test_zero(self):
        """Zero sources → MISSING_SECRET."""
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=None, env=None, flags=FLAGS, label=LABEL)
        assert exc.value.code == "MISSING_SECRET"
        assert "is required" in str(exc.value)

    def test_two_value_and_env(self):
        """Two sources → AMBIGUOUS_SECRET."""
        with pytest.raises(CliError) as exc:
            resolve_secret(value="x", file=None, env="Y", flags=FLAGS, label=LABEL)
        assert exc.value.code == "AMBIGUOUS_SECRET"
        assert "only one of" in str(exc.value)

    def test_three(self, tmp_path):
        """All three sources → AMBIGUOUS_SECRET."""
        f = tmp_path / "k"
        f.write_text("y", encoding="utf-8")
        with pytest.raises(CliError) as exc:
            resolve_secret(value="x", file=f, env="Y", flags=FLAGS, label=LABEL)
        assert exc.value.code == "AMBIGUOUS_SECRET"


class TestEmptySecrets:
    """Empty secrets are rejected with friendly errors per source."""

    def test_value_empty(self):
        """Empty literal --key → SECRET_VALUE_EMPTY."""
        with pytest.raises(CliError) as exc:
            resolve_secret(value="", file=None, env=None, flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_VALUE_EMPTY"

    def test_file_empty(self, tmp_path):
        """Empty --key-file → SECRET_FILE_EMPTY."""
        f = tmp_path / "k"
        f.write_text("", encoding="utf-8")
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=f, env=None, flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_FILE_EMPTY"

    def test_file_whitespace_only(self, tmp_path):
        """A whitespace-only file is empty after .strip() → SECRET_FILE_EMPTY."""
        f = tmp_path / "k"
        f.write_text("   \n\t\n", encoding="utf-8")
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=f, env=None, flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_FILE_EMPTY"

    def test_env_empty(self, monkeypatch):
        """Empty --key-env value → SECRET_ENV_EMPTY."""
        monkeypatch.setenv("MMC_TEST_SECRET", "")
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=None, env="MMC_TEST_SECRET", flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_ENV_EMPTY"


class TestNotFound:
    """Source-specific not-found errors."""

    def test_file_missing(self, tmp_path):
        """Nonexistent --key-file path → SECRET_FILE_NOT_FOUND."""
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=tmp_path / "missing", env=None, flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_FILE_NOT_FOUND"

    def test_env_unset(self, monkeypatch):
        """Unset --key-env variable → SECRET_ENV_NOT_SET."""
        monkeypatch.delenv("MMC_TEST_NOT_SET", raising=False)
        with pytest.raises(CliError) as exc:
            resolve_secret(value=None, file=None, env="MMC_TEST_NOT_SET", flags=FLAGS, label=LABEL)
        assert exc.value.code == "SECRET_ENV_NOT_SET"
