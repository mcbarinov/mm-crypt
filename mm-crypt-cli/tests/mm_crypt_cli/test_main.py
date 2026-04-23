"""Tests for the top-level argparse dispatcher in `mm_crypt_cli.main`."""

from importlib.metadata import version as _pkg_version

from mm_crypt_cli.main import app


class TestBareInvocation:
    """`mm-crypt` with no arguments prints full help and exits 0 (not argparse's usage-error 2)."""

    def test_no_args_prints_help(self, runner):
        """Bare invocation routes through `parser.print_help()` and returns 0."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        # Full help lists every top-level group/command, not just the one-line usage.
        for name in ("fernet", "openssl", "scrypt", "editor"):
            assert name in result.stdout


class TestVersion:
    """`--version` / `-V` prints the installed package version and exits 0."""

    def test_long_flag(self, runner):
        """`--version` prints `mm-crypt <ver>` to stdout."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert _pkg_version("mm-crypt-cli") in result.stdout

    def test_short_flag(self, runner):
        """`-V` is an alias of `--version`."""
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert _pkg_version("mm-crypt-cli") in result.stdout


class TestUnknownCommands:
    """Argparse rejects unknown groups/commands with exit code 2."""

    def test_unknown_group(self, runner):
        """An unknown group name yields argparse's usage error (exit 2)."""
        result = runner.invoke(app, ["bogus"])
        assert result.exit_code == 2

    def test_unknown_subcommand(self, runner):
        """An unknown subcommand under a known group yields exit 2."""
        result = runner.invoke(app, ["fernet", "bogus"])
        assert result.exit_code == 2
