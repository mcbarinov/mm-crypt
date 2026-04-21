"""CLI app definition and initialization."""

from mm_clikit import TyperPlus

from mm_crypt_cli.cli.commands.hello import hello

app = TyperPlus(package_name="mm-crypt-cli", json_option=False)


@app.callback()
def main() -> None:
    """CLI and TUI editor for encrypted text files, built on mm-crypt."""


app.command()(hello)
