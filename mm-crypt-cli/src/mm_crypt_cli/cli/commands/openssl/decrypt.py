"""Decrypt AES-256-CBC ciphertext (OpenSSL-compatible, password-based)."""

from pathlib import Path
from typing import Annotated

import typer
from mm_clikit import CliError
from mm_crypt import openssl_aes256cbc
from mm_crypt.errors import DecryptionError, InvalidInputError

from mm_crypt_cli.cli.io import read_bytes_input, read_text_input, write_bytes_output, write_text_output
from mm_crypt_cli.cli.secrets import resolve_secret

_PASSWORD_FLAGS = ("--password", "--password-file", "--password-env")


def decrypt(
    password: Annotated[
        str | None,
        typer.Option("--password", "-p", help="Password value (insecure — prefer --password-file or --password-env)."),
    ] = None,
    password_file: Annotated[
        Path | None, typer.Option("--password-file", help="File whose stripped contents are the password.")
    ] = None,
    password_env: Annotated[str | None, typer.Option("--password-env", help="Environment variable holding the password.")] = None,
    input_file: Annotated[Path | None, typer.Option("--input", "-i", help="Input file (default: stdin).")] = None,
    output_file: Annotated[Path | None, typer.Option("--output", "-o", help="Output file (default: stdout).")] = None,
    binary: Annotated[
        bool,
        typer.Option("--binary", "-b", help="Read raw ciphertext and emit raw bytes. Default: base64 in, UTF-8 text out."),
    ] = False,
) -> None:
    """Decrypt from --input (or stdin) using AES-256-CBC with PBKDF2; OpenSSL-compatible."""
    resolved_password = resolve_secret(
        value=password, file=password_file, env=password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    try:
        if binary:
            plaintext_bytes = openssl_aes256cbc.decrypt_bytes(data=read_bytes_input(input_file), password=resolved_password)
            write_bytes_output(plaintext_bytes, output_file)
        else:
            plaintext = openssl_aes256cbc.decrypt_base64(data=read_text_input(input_file), password=resolved_password)
            write_text_output(plaintext, output_file)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_INPUT") from exc
    except DecryptionError as exc:
        raise CliError(str(exc), "DECRYPTION_FAILED") from exc
