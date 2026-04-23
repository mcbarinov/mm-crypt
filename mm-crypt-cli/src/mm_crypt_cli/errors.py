"""Application error types."""


class CliError(Exception):
    """Recoverable CLI error.

    Caught at the top of the CLI dispatcher (``mm_crypt_cli.main.app``),
    written to stderr as ``Error: <message> [<CODE>]`` and mapped to exit code 1.
    """

    def __init__(self, message: str, code: str) -> None:
        """Initialize with a human-readable message and machine-readable code."""
        super().__init__(message)
        self.code = code  # Machine-readable error code (UPPER_SNAKE_CASE)
