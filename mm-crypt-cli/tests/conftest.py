"""Shared pytest fixtures for mm-crypt-cli."""

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """In-process Typer CLI runner — used by every command-level test."""
    return CliRunner()
