"""Decrypt a Fernet token with a Fernet key."""

import argparse
from pathlib import Path

from mm_crypt import fernet
from mm_crypt.errors import DecryptionError, InvalidInputError

from mm_crypt_cli.errors import CliError
from mm_crypt_cli.io import read_text_input, write_text_output
from mm_crypt_cli.secrets import resolve_secret

_KEY_FLAGS = ("--key", "--key-file", "--key-env")


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "decrypt",
        aliases=["d"],
        help="Decrypt a Fernet token with a Fernet key.",
        description="Decrypt a Fernet token from --input (or stdin) and emit the UTF-8 plaintext.",
    )
    parser.add_argument("--key", "-k", default=None, help="Fernet key value (insecure — prefer --key-file or --key-env).")
    parser.add_argument("--key-file", default=None, type=Path, help="File whose stripped contents are the Fernet key.")
    parser.add_argument("--key-env", default=None, help="Environment variable holding the Fernet key.")
    parser.add_argument("--input", "-i", dest="input_file", default=None, type=Path, help="Input file (default: stdin).")
    parser.add_argument("--output", "-o", dest="output_file", default=None, type=Path, help="Output file (default: stdout).")
    parser.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> None:
    """Decrypt a Fernet token from the chosen source with the resolved key."""
    resolved_key = resolve_secret(value=args.key, file=args.key_file, env=args.key_env, flags=_KEY_FLAGS, label="Fernet key")
    # Strip surrounding whitespace so an editor-appended trailing newline on the token file doesn't break decryption.
    token = read_text_input(args.input_file).strip()
    try:
        plaintext = fernet.decrypt(token=token, key=resolved_key)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_KEY") from exc
    except DecryptionError as exc:
        raise CliError(str(exc), "DECRYPTION_FAILED") from exc
    write_text_output(plaintext, args.output_file)
