"""Composition root — holds shared application state."""

from mm_crypt_cli.config import Config


class Core:
    """Application composition root.

    Holds the resolved Config. Extended in later steps when the TUI editor
    needs persistent state (recent files, settings, etc.).
    """

    def __init__(self, config: Config) -> None:
        """Build Core from a resolved configuration."""
        self.config = config  # Application configuration

    def close(self) -> None:
        """Release resources — no-op until we add state that needs cleanup."""
