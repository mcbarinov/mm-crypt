"""Shared fixtures for fernet command tests."""

from collections.abc import Callable

import pytest
from mm_crypt_cli.main import app


@pytest.fixture
def make_key(runner) -> Callable[[], str]:
    """Return a factory that produces a fresh Fernet key via the keygen CLI.

    Retries on keys starting with ``-`` because argparse (unlike the old typer
    wrapper) interprets such values as flags when passed after ``--key``. Real
    users hit the same issue and are steered to ``--key-file`` / ``--key-env``;
    for tests that want the `` --key <value>`` form, we just roll again — the
    probability is about 1.6% per attempt (2 / 64 base64 leading chars).
    """

    def _make() -> str:
        for _ in range(10):
            result = runner.invoke(app, ["fernet", "keygen"])
            assert result.exit_code == 0
            key = result.stdout.strip()
            if not key.startswith("-"):
                return key
        msg = "make_key: 10 consecutive keys started with '-' — generator is broken"
        raise RuntimeError(msg)

    return _make
