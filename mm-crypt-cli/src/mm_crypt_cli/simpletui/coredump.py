"""Disable core dumps so a crashing process does not leak plaintext.

A process crash can produce a core file — a snapshot of raw process memory,
which would include the plaintext editor buffer. Lowering ``RLIMIT_CORE`` to
zero before any sensitive data enters memory tells the kernel not to write a
core file for our process.

Best-effort: a host with hardened ``setrlimit`` policy may reject the call,
and a system-wide dump collector with elevated privileges (``systemd-coredump``,
macOS ``ReportCrash``) can still capture cores regardless of our limit. See
``docs/tui-editor.md`` for the full residual-risk discussion.
"""

import contextlib
import resource


def disable_core_dumps() -> None:
    """Lower ``RLIMIT_CORE`` to zero. Suppress errors — this is defense in depth."""
    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
