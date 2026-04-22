"""Encrypt data with scrypt (Tarsnap scrypt(1)-compatible, password-based)."""

from pathlib import Path
from typing import Annotated

import typer
from mm_clikit import CliError
from mm_crypt import scrypt
from mm_crypt.errors import InvalidInputError

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
    log_n: Annotated[
        int,
        typer.Option("--log-n", "-N", help=f"scrypt work factor N = 2^log_n. Range [{scrypt.MIN_LOG_N}, {scrypt.MAX_LOG_N}]."),
    ] = scrypt.DEFAULT_LOG_N,
    r: Annotated[
        int, typer.Option("--r", help=f"scrypt block size parameter r. Range [{scrypt.MIN_R}, {scrypt.MAX_R}].")
    ] = scrypt.DEFAULT_R,
    p: Annotated[
        int, typer.Option("--p", help=f"scrypt parallelization parameter p. Range [{scrypt.MIN_P}, {scrypt.MAX_P}].")
    ] = scrypt.DEFAULT_P,
) -> None:
    """Encrypt from --input (or stdin) using scrypt; Tarsnap scrypt(1)-compatible."""
    resolved_password = resolve_secret(
        value=password, file=password_file, env=password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    try:
        if binary:
            ciphertext = scrypt.encrypt_bytes(
                data=read_bytes_input(input_file), password=resolved_password, log_n=log_n, r=r, p=p
            )
            write_bytes_output(ciphertext, output_file)
        else:
            token = scrypt.encrypt_base64(data=read_text_input(input_file), password=resolved_password, log_n=log_n, r=r, p=p)
            write_text_output(token, output_file)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_INPUT") from exc
