"""Generate a new Fernet key."""

import argparse
import sys

from mm_crypt import fernet


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Wire this command into its group's subparsers."""
    parser = subparsers.add_parser(
        "keygen",
        aliases=["g"],
        help="Generate a new Fernet key.",
        description="Print a freshly generated Fernet key (URL-safe base64, 32 bytes of entropy).",
    )
    parser.set_defaults(func=_run)


def _run(_args: argparse.Namespace) -> None:
    """Print a freshly generated Fernet key."""
    sys.stdout.write(fernet.generate_key() + "\n")
    sys.stdout.flush()
