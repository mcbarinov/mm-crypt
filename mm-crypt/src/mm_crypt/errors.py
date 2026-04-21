"""Exception hierarchy shared by all mm_crypt modules.

Callers distinguish two failure modes:

- `InvalidInputError`: input is rejected before decryption — malformed key,
  missing magic header, bad base64, truncated data, unsupported version, or
  out-of-range KDF parameters. Retrying with a different password won't help.
- `DecryptionError`: input is structurally valid but couldn't be authenticated
  or decrypted. Typically wrong password; may also be tampered ciphertext — the
  two are deliberately collapsed so attackers gain no information.

`CryptError` is the common base — callers catch it for "any mm_crypt failure".
The hierarchy intentionally does NOT derive from `ValueError`: crypto errors
are security-sensitive, and matching the convention used by `cryptography`
(`InvalidToken`, `InvalidSignature`) keeps them out of generic `except ValueError`
handlers elsewhere in the caller's code.
"""


class CryptError(Exception):
    """Base class for all mm_crypt errors."""


class InvalidInputError(CryptError):
    """Input is rejected before decryption: malformed shape, bad encoding, or out-of-range parameters."""


class DecryptionError(CryptError):
    """Authentication or decryption failed — wrong password, or tampered ciphertext."""
