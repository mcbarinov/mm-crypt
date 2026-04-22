"""Generate a new Fernet key."""

from mm_clikit import print_plain
from mm_crypt import fernet


def keygen() -> None:
    """Print a freshly generated Fernet key (URL-safe base64, 32 bytes of entropy)."""
    print_plain(fernet.generate_key())
