"""Encrypt data with scrypt (Tarsnap scrypt(1)-compatible, password-based)."""

import argparse
from pathlib import Path

from mm_crypt import scrypt
from mm_crypt.errors import InvalidInputError

from mm_crypt_cli.errors import CliError
from mm_crypt_cli.io import read_bytes_input, read_text_input, write_bytes_output, write_text_output
from mm_crypt_cli.secrets import resolve_secret

_PASSWORD_FLAGS = ("--password", "--password-file", "--password-env")


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "encrypt",
        aliases=["e"],
        help="Encrypt data with scrypt (Tarsnap scrypt(1)-compatible).",
        description="Encrypt from --input (or stdin) using scrypt; Tarsnap scrypt(1)-compatible.",
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
        help="Read raw bytes and emit raw ciphertext. Default: UTF-8 text in, base64 out.",
    )
    parser.add_argument(
        "--log-n",
        "-N",
        dest="log_n",
        type=int,
        default=scrypt.DEFAULT_LOG_N,
        help=f"scrypt work factor N = 2^log_n. Range [{scrypt.MIN_LOG_N}, {scrypt.MAX_LOG_N}].",
    )
    parser.add_argument(
        "--r",
        dest="r",
        type=int,
        default=scrypt.DEFAULT_R,
        help=f"scrypt block size parameter r. Range [{scrypt.MIN_R}, {scrypt.MAX_R}].",
    )
    parser.add_argument(
        "--p",
        dest="p",
        type=int,
        default=scrypt.DEFAULT_P,
        help=f"scrypt parallelization parameter p. Range [{scrypt.MIN_P}, {scrypt.MAX_P}].",
    )
    parser.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> None:
    """Encrypt from the chosen source using scrypt with the requested KDF parameters."""
    password = resolve_secret(
        value=args.password, file=args.password_file, env=args.password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    try:
        if args.binary:
            ciphertext = scrypt.encrypt_bytes(
                data=read_bytes_input(args.input_file), password=password, log_n=args.log_n, r=args.r, p=args.p
            )
            write_bytes_output(ciphertext, args.output_file)
        else:
            token = scrypt.encrypt_base64(
                data=read_text_input(args.input_file), password=password, log_n=args.log_n, r=args.r, p=args.p
            )
            write_text_output(token, args.output_file)
    except InvalidInputError as exc:
        raise CliError(str(exc), "INVALID_INPUT") from exc
