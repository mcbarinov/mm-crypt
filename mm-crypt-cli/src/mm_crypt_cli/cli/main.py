"""CLI app definition and initialization."""

import typer
from mm_clikit import CoreContext, TyperPlus

from mm_crypt_cli.cli.commands.fernet.decrypt import decrypt as fernet_decrypt
from mm_crypt_cli.cli.commands.fernet.encrypt import encrypt as fernet_encrypt
from mm_crypt_cli.cli.commands.fernet.keygen import keygen as fernet_keygen
from mm_crypt_cli.config import Config
from mm_crypt_cli.core.core import Core

app = TyperPlus(package_name="mm-crypt-cli", json_option=False)


@app.callback()
def main(ctx: typer.Context) -> None:
    """CLI and TUI editor for encrypted text files, built on mm-crypt."""
    core = Core(Config())
    ctx.call_on_close(core.close)
    ctx.obj = CoreContext[Core, None](core=core, out=None)


fernet_app = TyperPlus(json_option=False)
fernet_app.command(name="keygen", aliases=["g"])(fernet_keygen)
fernet_app.command(name="encrypt", aliases=["e"])(fernet_encrypt)
fernet_app.command(name="decrypt", aliases=["d"])(fernet_decrypt)
app.add_typer(fernet_app, name="fernet", aliases=["f"], help="Fernet symmetric encryption commands.")
