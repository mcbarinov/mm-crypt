"""Resolve a secret (key or password) from mutually exclusive CLI sources."""

import os
from pathlib import Path

from mm_crypt_cli.errors import CliError


def resolve_secret(
    *,
    value: str | None,
    file: Path | None,
    env: str | None,
    flags: tuple[str, str, str],
    label: str,
) -> str:
    """Resolve a secret from exactly one of three mutually exclusive sources.

    Args:
        value: Literal secret passed on argv.
        file: Path to a file whose stripped contents are the secret.
        env: Name of an environment variable holding the secret.
        flags: CLI flag spellings ``(value_flag, file_flag, env_flag)`` for error messages.
        label: Human label ("Fernet key", "password") for error messages.

    Raises:
        CliError: if zero or multiple sources are supplied, or the chosen source is unreadable / empty.

    """
    value_flag, file_flag, env_flag = flags
    provided = sum(x is not None for x in (value, file, env))
    if provided == 0:
        raise CliError(
            f"{label} is required. Provide one of {value_flag}, {file_flag}, or {env_flag}.",
            "MISSING_SECRET",
        )
    if provided > 1:
        raise CliError(
            f"Provide only one of {value_flag}, {file_flag}, or {env_flag}.",
            "AMBIGUOUS_SECRET",
        )

    if value is not None:
        if not value:
            raise CliError(f"{label} is empty.", "SECRET_VALUE_EMPTY")
        return value

    if file is not None:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise CliError(f"{label} file not found: {file}", "SECRET_FILE_NOT_FOUND") from exc
        except OSError as exc:
            raise CliError(f"Cannot read {label} file {file}: {exc}", "SECRET_FILE_READ_ERROR") from exc
        secret = content.strip()
        if not secret:
            raise CliError(f"{label} file is empty: {file}", "SECRET_FILE_EMPTY")
        return secret

    if env is not None:
        env_value = os.environ.get(env)
        if env_value is None:
            raise CliError(f"Environment variable not set: {env}", "SECRET_ENV_NOT_SET")
        if not env_value:
            raise CliError(f"Environment variable is empty: {env}", "SECRET_ENV_EMPTY")
        return env_value

    # Unreachable: exactly one of value/file/env is non-None (validated above).
    raise CliError(f"Internal error resolving {label}.", "INTERNAL_ERROR")
