"""Centralized application configuration."""

from typing import ClassVar

from mm_clikit import BaseConfig


class Config(BaseConfig):
    """Application-wide configuration for mm-crypt-cli.

    Currently empty — the crypto commands need no persistent state. Subclassing
    keeps the architectural shape (``Core`` owns a ``Config``) so that future
    additions (e.g. TUI editor settings) have a place to land.
    """

    app_name: ClassVar[str] = "mm-crypt"
