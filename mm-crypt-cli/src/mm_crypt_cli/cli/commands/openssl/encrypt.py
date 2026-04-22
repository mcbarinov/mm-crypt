"""Encrypt data with AES-256-CBC (OpenSSL-compatible, password-based)."""

from pathlib import Path
from typing import Annotated

import typer
from mm_crypt import openssl_aes256cbc

from mm_crypt_cli.cli.io import read_bytes_input, read_text_input, write_bytes_output, write_text_output
from mm_crypt_cli.cli.secrets import resolve_secret

_PASSWORD_FLAGS = ("--password", "--password-file", "--password-env")


def encrypt(
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
        typer.Option("--binary", "-b", help="Read raw bytes and emit raw ciphertext. Default: UTF-8 text in, base64 out."),
    ] = False,
) -> None:
    """Encrypt from --input (or stdin) using AES-256-CBC with PBKDF2; OpenSSL-compatible."""
    resolved_password = resolve_secret(
        value=password, file=password_file, env=password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    if binary:
        ciphertext = openssl_aes256cbc.encrypt_bytes(data=read_bytes_input(input_file), password=resolved_password)
        write_bytes_output(ciphertext, output_file)
    else:
        token = openssl_aes256cbc.encrypt_base64(data=read_text_input(input_file), password=resolved_password)
        write_text_output(token, output_file)
