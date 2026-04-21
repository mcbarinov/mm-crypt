"""Placeholder hello command — smoke test for the CLI wiring."""

from typing import Annotated

import typer
from mm_clikit import print_plain


def hello(
    name: Annotated[str, typer.Argument(help="Name to greet.")] = "world",
) -> None:
    """Print a greeting. Used to verify the CLI is wired up correctly."""
    target = name.strip() or "world"
    print_plain(f"Hello, {target}!")
