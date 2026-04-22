"""CLI app definition and initialization."""

import typer
from mm_clikit import CoreContext, TyperPlus

from mm_crypt_cli.cli.commands.fernet.decrypt import decrypt as fernet_decrypt
from mm_crypt_cli.cli.commands.fernet.encrypt import encrypt as fernet_encrypt
from mm_crypt_cli.cli.commands.fernet.keygen import keygen as fernet_keygen
from mm_crypt_cli.cli.commands.openssl.decrypt import decrypt as openssl_decrypt
from mm_crypt_cli.cli.commands.openssl.encrypt import encrypt as openssl_encrypt
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

openssl_app = TyperPlus(json_option=False)


@openssl_app.callback()
def _openssl_group() -> None:
    """OpenSSL-compatible AES-256-CBC password-based encryption commands.

    Fully interoperable with the `openssl enc` CLI binary. Equivalent invocations via `openssl(1)`:

    encrypt (base64): openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -base64 -pass pass:PASS -in in.txt -out out.b64

    decrypt (base64): openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -base64 -pass pass:PASS -in in.b64 -out out.txt

    encrypt (--binary): openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -pass pass:PASS -in in.bin -out out.bin

    decrypt (--binary): openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass pass:PASS -in in.bin -out out.bin
    """


openssl_app.command(name="encrypt", aliases=["e"])(openssl_encrypt)
openssl_app.command(name="decrypt", aliases=["d"])(openssl_decrypt)
app.add_typer(openssl_app, name="openssl", aliases=["o"])
