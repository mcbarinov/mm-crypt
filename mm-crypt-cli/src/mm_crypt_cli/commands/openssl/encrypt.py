"""Encrypt data with AES-256-CBC (OpenSSL-compatible, password-based)."""

import argparse
from pathlib import Path

from mm_crypt import openssl_aes256cbc

from mm_crypt_cli.io import read_bytes_input, read_text_input, write_bytes_output, write_text_output
from mm_crypt_cli.secrets import resolve_secret

_PASSWORD_FLAGS = ("--password", "--password-file", "--password-env")


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "encrypt",
        aliases=["e"],
        help="Encrypt data with AES-256-CBC (OpenSSL-compatible).",
        description="Encrypt from --input (or stdin) using AES-256-CBC with PBKDF2; OpenSSL-compatible.",
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
    parser.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> None:
    """Encrypt from the chosen source using AES-256-CBC."""
    password = resolve_secret(
        value=args.password, file=args.password_file, env=args.password_env, flags=_PASSWORD_FLAGS, label="password"
    )
    if args.binary:
        ciphertext = openssl_aes256cbc.encrypt_bytes(data=read_bytes_input(args.input_file), password=password)
        write_bytes_output(ciphertext, args.output_file)
    else:
        token = openssl_aes256cbc.encrypt_base64(data=read_text_input(args.input_file), password=password)
        write_text_output(token, args.output_file)
