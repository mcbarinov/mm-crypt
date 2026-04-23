"""Runtime defenses applied before the TUI starts.

Two concerns, one module:

1. Textual reads several environment variables that, when set, cause it to
   write to disk (log file, keystroke log, screen-content SVG screenshot).
   Any of those would leak plaintext buffer contents out of memory. We pop
   them from ``os.environ`` before ``App.run()`` so Textual sees them unset
   regardless of the caller's shell environment.

2. A crashing process can produce a core dump — a file containing raw
   process memory, including the plaintext buffer. We lower ``RLIMIT_CORE``
   to zero so the kernel will not write one, best-effort.

Neither is a complete defense against a hostile local attacker with
arbitrary shell access (they can set LD_PRELOAD, attach a debugger, etc.),
but each closes a realistic accidental-leak path.
"""

import contextlib
import os
import resource

# Textual env vars that cause disk writes. Source: textual 8.2.4 audit.
# - TEXTUAL_LOG: file path; TextualHandler appends all log output.
# - TEXTUAL_DEBUG: "1" enables XTermParser keystroke log at ./keys.log.
# - TEXTUAL_SCREENSHOT: seconds; on exit writes an SVG of the rendered screen
#   (which includes TextArea contents) to disk.
# - TEXTUAL_SCREENSHOT_LOCATION / _FILENAME: where the above SVG lands.
_RISKY_TEXTUAL_ENV: tuple[str, ...] = (
    "TEXTUAL_LOG",
    "TEXTUAL_DEBUG",
    "TEXTUAL_SCREENSHOT",
    "TEXTUAL_SCREENSHOT_LOCATION",
    "TEXTUAL_SCREENSHOT_FILENAME",
)


def apply_hardening() -> None:
    """Scrub risky env vars and disable core dumps. Must run before App.run()."""
    for key in _RISKY_TEXTUAL_ENV:
        os.environ.pop(key, None)
    # Best-effort: on a hardened host that forbids adjusting the core limit,
    # we don't want to prevent the editor from launching.
    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
