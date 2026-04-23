"""Open the TUI editor on a scrypt-encrypted text file."""

import argparse
import sys
from getpass import getpass
from pathlib import Path

from mm_crypt import scrypt
from mm_crypt.errors import DecryptionError, InvalidInputError

from mm_crypt_cli.errors import CliError


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "editor",
        aliases=["e"],
        help="Open the TUI editor on a scrypt-encrypted text file.",
        description=(
            "Open a TUI editor on a scrypt-encrypted text file.\n\n"
            "If the file exists, prompts for the password once and decrypts it. If the file\n"
            "does not exist, prompts twice (password + confirmation) and opens an empty\n"
            "buffer; nothing is written to disk until the first Ctrl+S save.\n\n"
            "The password is never accepted via CLI flag or environment variable — the TUI\n"
            "is an interactive tool, and argv/env leak to shell history and `ps`."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", type=Path, help="Encrypted document path. Created on first save if it does not exist.")
    parser.add_argument("--view", "-V", action="store_true", help="Open read-only; disable save.")
    parser.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> None:
    """Decrypt (or prepare a new buffer), then run the interactive editor until quit."""
    # Windows is not supported: the editor relies on POSIX termios, fcntl, and SIGWINCH.
    # The platform check runs before the tui imports so that loading this module
    # (and thus the whole CLI) still succeeds on Windows for unrelated commands.
    if sys.platform == "win32":
        raise CliError("The TUI editor is not supported on Windows.", "UNSUPPORTED_PLATFORM")
    # Imports deferred past the platform gate because `coredump` imports `resource`
    # and `editor` transitively imports `termios`/`tty`/`fcntl` — all POSIX-only.
    from mm_crypt_cli.simpletui.coredump import disable_core_dumps  # noqa: PLC0415
    from mm_crypt_cli.simpletui.editor import EditorApp  # noqa: PLC0415

    # Disable core dumps before any sensitive data (password, decrypted plaintext)
    # enters process memory. See docs/tui-editor.md for the full security model.
    disable_core_dumps()
    # Follow symlinks so we write through to the real file instead of replacing
    # the symlink itself (matches vim/emacs default "write-through" behavior).
    path: Path = args.path.resolve()
    view: bool = args.view
    if path.exists():
        if not path.is_file():
            raise CliError(f"Not a file: {path}", "NOT_A_FILE")
        try:
            ciphertext = path.read_bytes()
        except OSError as exc:
            raise CliError(f"Cannot read {path}: {exc}", "READ_ERROR") from exc
        password = getpass(f"Password for {path}: ")
        if not password:
            raise CliError("Password is empty.", "EMPTY_PASSWORD")
        try:
            plaintext_bytes = scrypt.decrypt_bytes(data=ciphertext, password=password)
        except InvalidInputError as exc:
            raise CliError(str(exc), "INVALID_INPUT") from exc
        except DecryptionError as exc:
            raise CliError(str(exc), "DECRYPTION_FAILED") from exc
        try:
            initial_text = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CliError("File contents are not valid UTF-8 text.", "NOT_TEXT") from exc
    else:
        if view:
            raise CliError(f"File does not exist: {path}", "NOT_FOUND")
        # Fail early (before the password prompt) if the parent directory is missing:
        # atomic save needs to create a tmp sibling in parent, which requires it to exist.
        if not path.parent.exists():
            raise CliError(f"Parent directory does not exist: {path.parent}", "PARENT_NOT_FOUND")
        password = getpass(f"New password for {path}: ")
        if not password:
            raise CliError("Password is empty.", "EMPTY_PASSWORD")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            raise CliError("Passwords do not match.", "PASSWORD_MISMATCH")
        initial_text = ""

    EditorApp(path=path, password=password, initial_text=initial_text, readonly=view).run()
