"""Tests for `mm-crypt editor` pre-run error branches.

These cover every `CliError` path in `commands/editor.py` that triggers before
the TUI editor actually starts (`EditorApp.run`). The interactive TUI itself
is out of scope — it requires a real terminal and is verified manually.
"""

import sys

import pytest
from mm_crypt import scrypt
from mm_crypt_cli.main import app

# Fastest legal scrypt KDF — keeps every call under ~1 ms / ~1 MiB RAM.
_FAST_LOG_N = 10


def _encrypt_fast(plaintext: bytes, password: str) -> bytes:
    """Encrypt `plaintext` with the minimum scrypt KDF cost."""
    return scrypt.encrypt_bytes(data=plaintext, password=password, log_n=_FAST_LOG_N)


@pytest.fixture
def stub_getpass(monkeypatch):
    """Return a factory that installs a queued `getpass` stub.

    The factory takes a list of return values; calls to `getpass` pop from the
    front of the list in order. An empty queue raises — surfacing unexpected
    extra prompts as test failures rather than hangs.
    """

    def _install(responses: list[str]) -> None:
        queue = list(responses)

        def fake(prompt: str = "") -> str:  # noqa: ARG001
            return queue.pop(0)

        monkeypatch.setattr("mm_crypt_cli.commands.editor.getpass", fake)

    return _install


class TestPathValidation:
    """File-system pre-checks fail before any password prompt."""

    def test_not_a_file(self, runner, err_text, tmp_path):
        """A path that points to a directory raises NOT_A_FILE."""
        result = runner.invoke(app, ["editor", str(tmp_path)])
        assert result.exit_code == 1
        assert "NOT_A_FILE" in err_text(result)

    def test_view_on_missing_file(self, runner, err_text, tmp_path):
        """`--view` on a nonexistent path raises NOT_FOUND."""
        result = runner.invoke(app, ["editor", str(tmp_path / "missing.scrypt"), "--view"])
        assert result.exit_code == 1
        assert "NOT_FOUND" in err_text(result)

    def test_parent_not_found(self, runner, err_text, tmp_path):
        """Creating a new file under a missing parent directory raises PARENT_NOT_FOUND."""
        result = runner.invoke(app, ["editor", str(tmp_path / "missing_dir" / "new.scrypt")])
        assert result.exit_code == 1
        assert "PARENT_NOT_FOUND" in err_text(result)


class TestPasswordBranches:
    """Interactive `getpass` flows for both existing and new files."""

    def test_empty_password_existing_file(self, runner, err_text, tmp_path, stub_getpass):
        """An empty password on an existing file raises EMPTY_PASSWORD before decryption."""
        path = tmp_path / "secret.scrypt"
        path.write_bytes(_encrypt_fast(b"hello", "pw"))
        stub_getpass([""])
        result = runner.invoke(app, ["editor", str(path)])
        assert result.exit_code == 1
        assert "EMPTY_PASSWORD" in err_text(result)

    def test_empty_password_new_file(self, runner, err_text, tmp_path, stub_getpass):
        """An empty password on a new file raises EMPTY_PASSWORD before the confirm prompt."""
        stub_getpass([""])
        result = runner.invoke(app, ["editor", str(tmp_path / "new.scrypt")])
        assert result.exit_code == 1
        assert "EMPTY_PASSWORD" in err_text(result)

    def test_password_mismatch_new_file(self, runner, err_text, tmp_path, stub_getpass):
        """Confirmation that differs from the first password raises PASSWORD_MISMATCH."""
        stub_getpass(["pw", "different"])
        result = runner.invoke(app, ["editor", str(tmp_path / "new.scrypt")])
        assert result.exit_code == 1
        assert "PASSWORD_MISMATCH" in err_text(result)


class TestCiphertextBranches:
    """Errors surfaced from the scrypt library on read."""

    def test_decryption_failed(self, runner, err_text, tmp_path, stub_getpass):
        """A wrong password on a valid scrypt blob raises DECRYPTION_FAILED."""
        path = tmp_path / "secret.scrypt"
        path.write_bytes(_encrypt_fast(b"hello", "right"))
        stub_getpass(["wrong"])
        result = runner.invoke(app, ["editor", str(path)])
        assert result.exit_code == 1
        assert "DECRYPTION_FAILED" in err_text(result)

    def test_invalid_input(self, runner, err_text, tmp_path, stub_getpass):
        """A file that is not a scrypt blob at all raises INVALID_INPUT."""
        path = tmp_path / "garbage.scrypt"
        path.write_bytes(b"not a scrypt file")
        stub_getpass(["pw"])
        result = runner.invoke(app, ["editor", str(path)])
        assert result.exit_code == 1
        assert "INVALID_INPUT" in err_text(result)

    def test_not_text(self, runner, err_text, tmp_path, stub_getpass):
        """Correctly decrypted plaintext that is not valid UTF-8 raises NOT_TEXT."""
        path = tmp_path / "binary.scrypt"
        # 0xff/0xfe/0xfd are invalid UTF-8 start bytes.
        path.write_bytes(_encrypt_fast(b"\xff\xfe\xfd", "pw"))
        stub_getpass(["pw"])
        result = runner.invoke(app, ["editor", str(path)])
        assert result.exit_code == 1
        assert "NOT_TEXT" in err_text(result)


class TestPlatformGate:
    """The TUI refuses to start on Windows — before the POSIX-only imports run."""

    def test_unsupported_platform(self, runner, err_text, tmp_path, monkeypatch):
        """`sys.platform == 'win32'` raises UNSUPPORTED_PLATFORM before any simpletui import."""
        monkeypatch.setattr(sys, "platform", "win32")
        result = runner.invoke(app, ["editor", str(tmp_path / "anything.scrypt")])
        assert result.exit_code == 1
        assert "UNSUPPORTED_PLATFORM" in err_text(result)
