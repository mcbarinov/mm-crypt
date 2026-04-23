"""CLI entry point — argparse-based dispatcher.

Command tree::

    mm-crypt fernet  (f)  keygen   (g)
                          encrypt  (e)
                          decrypt  (d)
    mm-crypt openssl (o)  encrypt  (e)
                          decrypt  (d)
    mm-crypt scrypt  (s)  encrypt  (e)
                          decrypt  (d)
    mm-crypt editor  (e)  <path>

Error handling: every recoverable failure raises :class:`mm_crypt_cli.errors.CliError`.
:func:`app` catches it, writes ``Error: <message> [<CODE>]`` to stderr and
returns exit code ``1``. argparse usage errors (``SystemExit(2)``) and
``--help`` / ``--version`` (``SystemExit(0)``) flow through unchanged.

The module deliberately avoids any third-party CLI framework — only
``argparse`` from the stdlib — to keep the installed dependency graph minimal
for a security-sensitive tool.
"""

import argparse
import sys
from collections.abc import Callable
from importlib.metadata import version as _pkg_version

from mm_crypt_cli.commands import editor
from mm_crypt_cli.commands.fernet import decrypt as fernet_decrypt
from mm_crypt_cli.commands.fernet import encrypt as fernet_encrypt
from mm_crypt_cli.commands.fernet import keygen as fernet_keygen
from mm_crypt_cli.commands.openssl import decrypt as openssl_decrypt
from mm_crypt_cli.commands.openssl import encrypt as openssl_encrypt
from mm_crypt_cli.commands.scrypt import decrypt as scrypt_decrypt
from mm_crypt_cli.commands.scrypt import encrypt as scrypt_encrypt
from mm_crypt_cli.errors import CliError

_OPENSSL_GROUP_DESCRIPTION = """\
OpenSSL-compatible AES-256-CBC password-based encryption commands.

Fully interoperable with the `openssl enc` CLI binary. Equivalent invocations via `openssl(1)`:

encrypt (base64):   openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -base64 -pass pass:PASS -in in.txt -out out.b64
decrypt (base64):   openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -base64 -pass pass:PASS -in in.b64 -out out.txt
encrypt (--binary): openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -pass pass:PASS -in in.bin -out out.bin
decrypt (--binary): openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass pass:PASS -in in.bin -out out.bin
"""

_SCRYPT_GROUP_DESCRIPTION = """\
Tarsnap scrypt(1)-compatible password-based encryption commands.

Fully interoperable with the upstream `scrypt` CLI binary. Equivalent invocations via `scrypt(1)`:

encrypt (--binary): scrypt enc -P plain.bin cipher.bin  (password on stdin)
decrypt (--binary): scrypt dec -P cipher.bin plain.bin  (password on stdin)

Base64 mode wraps the same binary blob for text pipelines; `scrypt(1)` has no native base64 mode.

Install the reference CLI: `brew install scrypt` / `apt install scrypt` / `pacman -S scrypt`.
"""


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level parser with every subcommand wired in."""
    parser = argparse.ArgumentParser(
        prog="mm-crypt",
        description="CLI and TUI editor for encrypted text files, built on mm-crypt.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"mm-crypt {_pkg_version('mm-crypt-cli')}",
    )
    groups = parser.add_subparsers(dest="group", required=True, metavar="GROUP")

    # fernet
    fernet_parser = groups.add_parser(
        "fernet",
        aliases=["f"],
        help="Fernet symmetric encryption commands.",
        description="Fernet symmetric encryption commands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fernet_sub = fernet_parser.add_subparsers(dest="cmd", required=True, metavar="CMD")
    fernet_keygen.register(fernet_sub)
    fernet_encrypt.register(fernet_sub)
    fernet_decrypt.register(fernet_sub)

    # openssl
    openssl_parser = groups.add_parser(
        "openssl",
        aliases=["o"],
        help="OpenSSL-compatible AES-256-CBC password-based encryption commands.",
        description=_OPENSSL_GROUP_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    openssl_sub = openssl_parser.add_subparsers(dest="cmd", required=True, metavar="CMD")
    openssl_encrypt.register(openssl_sub)
    openssl_decrypt.register(openssl_sub)

    # scrypt
    scrypt_parser = groups.add_parser(
        "scrypt",
        aliases=["s"],
        help="Tarsnap scrypt(1)-compatible password-based encryption commands.",
        description=_SCRYPT_GROUP_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scrypt_sub = scrypt_parser.add_subparsers(dest="cmd", required=True, metavar="CMD")
    scrypt_encrypt.register(scrypt_sub)
    scrypt_decrypt.register(scrypt_sub)

    # editor — top-level (sibling of the fernet/openssl/scrypt groups, not nested under scrypt)
    editor.register(groups)

    return parser


def app(argv: list[str] | None = None) -> int:
    """Parse ``argv`` (or ``sys.argv[1:]``) and dispatch to the chosen command.

    Returns the process exit code:

    * ``0`` — command succeeded (or ``--help`` / ``--version`` was printed).
    * ``1`` — a recoverable :class:`CliError` was raised by the command.
    * ``2`` — argparse rejected the argv (unknown option, missing subcommand).

    Return semantics match what a ``mm-crypt = "...:app"`` console script entry
    expects: ``sys.exit(app())`` is how the generated wrapper invokes us.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    # ``func`` is installed on the leaf subparser by each command's ``register()``
    # via ``parser.set_defaults(func=_run)`` and retrieved off the resulting Namespace.
    func: Callable[[argparse.Namespace], None] = args.func
    try:
        func(args)
    except CliError as exc:
        sys.stderr.write(f"Error: {exc} [{exc.code}]\n")
        return 1
    return 0
