"""Decrypt scrypt ciphertext (Tarsnap scrypt(1)-compatible, password-based)."""

import argparse
from pathlib import Path

from mm_crypt import scrypt
from mm_crypt.errors import DecryptionError, InvalidInputError

from mm_crypt_cli.errors import CliError
from mm_crypt_cli.io import read_bytes_input, read_text_input, write_bytes_output, write_text_output
from mm_crypt_cli.secrets import resolve_secret

_PASSWORD_FLAGS = ("--password", "--password-file", "--password-env")


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "decrypt",
        aliases=["d"],
        help="Decrypt scrypt ciphertext (Tarsnap scrypt(1)-compatible).",
        description=(
            "Decrypt from --input (or stdin) using scrypt; Tarsnap scrypt(1)-compatible.\n"
            "KDF parameters (log_n, r, p) are read from the file header — no flags needed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--password", "-p", default=None, help="Password value (insecure — prefer --password-file or --password-env)."
    )
    parser.add_argument("--password-file", default=None, type=Path, help="File whose stripped contents are the password.")
    parser.add_argument("--password-env", default=None, help="Environment variable holding the password.")
    parser.add_argument("--input", "-i", dest="input_file", default=None, type=Path, help="Input file (default: stdin).")
    parser.add_argument("--output", "-o", dest="output_file", default=None, type=Path, help="Output file (default: stdout).")
    parser.add_argument(
        "--binary",
        "-b",
        action="store_true",
        help="Read raw ciphertext and emit raw bytes. Default: base64 in, UTF-8 text out.",
    )
    parser.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> None:
    """Decrypt from the chosen source using scrypt."""
    password = resolve_secret(
        value=args.password, file=args.password_file, env=args.password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    try:
        if args.binary:
            plaintext_bytes = scrypt.decrypt_bytes(data=read_bytes_input(args.input_file), password=password)
            write_bytes_output(plaintext_bytes, args.output_file)
        else:
            plaintext = scrypt.decrypt_base64(data=read_text_input(args.input_file), password=password)
            write_text_output(plaintext, args.output_file)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_INPUT") from exc
    except DecryptionError as exc:
        raise CliError(str(exc), "DECRYPTION_FAILED") from exc
