"""Encrypt text with a Fernet key."""

from pathlib import Path
from typing import Annotated

import typer
from mm_clikit import CliError
from mm_crypt import fernet
from mm_crypt.errors import InvalidInputError

from mm_crypt_cli.cli.io import read_text_input, write_text_output
from mm_crypt_cli.cli.secrets import resolve_secret

_KEY_FLAGS = ("--key", "--key-file", "--key-env")


def encrypt(
    key: Annotated[
        str | None,
        typer.Option("--key", "-k", help="Fernet key value (insecure — prefer --key-file or --key-env)."),
    ] = None,
    key_file: Annotated[Path | None, typer.Option("--key-file", help="File whose stripped contents are the Fernet key.")] = None,
    key_env: Annotated[str | None, typer.Option("--key-env", help="Environment variable holding the Fernet key.")] = None,
    input_file: Annotated[Path | None, typer.Option("--input", "-i", help="Input file (default: stdin).")] = None,
    output_file: Annotated[Path | None, typer.Option("--output", "-o", help="Output file (default: stdout).")] = None,
) -> None:
    """Encrypt UTF-8 text from --input (or stdin) and emit a Fernet token."""
    resolved_key = resolve_secret(value=key, file=key_file, env=key_env, flags=_KEY_FLAGS, label="Fernet key")
    plaintext = read_text_input(input_file)
    try:
        token = fernet.encrypt(data=plaintext, key=resolved_key)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_KEY") from exc
    write_text_output(token, output_file)
