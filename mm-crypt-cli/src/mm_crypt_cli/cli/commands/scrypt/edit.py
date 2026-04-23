"""Open the TUI editor on a scrypt-encrypted text file."""

from getpass import getpass
from pathlib import Path
from typing import Annotated

import typer
from mm_clikit import CliError
from mm_crypt import scrypt
from mm_crypt.errors import DecryptionError, InvalidInputError

from mm_crypt_cli.tui.app import EditorApp
from mm_crypt_cli.tui.hardening import apply_hardening


def edit(
    path: Annotated[Path, typer.Argument(help="Encrypted document path. Created on first save if it does not exist.")],
    view: Annotated[bool, typer.Option("--view", "-V", help="Open read-only; disable save.")] = False,
) -> None:
    """Open a TUI editor on a scrypt-encrypted text file.

    If the file exists, prompts for the password once and decrypts it. If the file
    does not exist, prompts twice (password + confirmation) and opens an empty
    buffer; nothing is written to disk until the first Ctrl+S save.

    The password is never accepted via CLI flag or environment variable — the TUI
    is an interactive tool, and argv/env leak to shell history and `ps`.
    """
    # Harden first: disables core dumps and scrubs Textual env vars before we
    # put sensitive data (password, decrypted plaintext) into process memory.
    apply_hardening()
    # Follow symlinks so we write through to the real file instead of replacing
    # the symlink itself (matches vim/emacs default "write-through" behavior).
    path = path.resolve()
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
