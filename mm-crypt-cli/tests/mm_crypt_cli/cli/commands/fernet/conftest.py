"""Shared fixtures for fernet command tests."""

from collections.abc import Callable

import pytest
from click.testing import Result
from mm_crypt_cli.cli.main import app
from typer.testing import CliRunner


@pytest.fixture
def make_key(runner: CliRunner) -> Callable[[], str]:
    """Return a factory that produces a fresh Fernet key via the keygen CLI."""

    def _make() -> str:
        result = runner.invoke(app, ["fernet", "keygen"])
        assert result.exit_code == 0
        return result.stdout.strip()

    return _make


@pytest.fixture
def err_text() -> Callable[[Result], str]:
    """Return a callable that extracts combined stdout+stderr from a CliRunner Result."""

    def _extract(result: Result) -> str:
        return getattr(result, "stderr", "") + result.output

    return _extract
