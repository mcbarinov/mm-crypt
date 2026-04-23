"""Hand-rolled TUI editor for scrypt-encrypted text files.

We deliberately do not depend on Textual, urwid, prompt_toolkit, or curses.
Such libraries have a history of disk-write side channels driven by env vars
(``TEXTUAL_LOG``, ``NCURSES_TRACE``, screenshot facilities) — defending
against them requires an env-var blocklist that goes stale with each new
upstream version. This package instead uses ``termios`` + hardcoded ANSI
escape sequences so the class of "library writes buffer to disk" risks is
empty rather than scrubbed.

Module layout (one-way dependency: editor → view → buffer/keys/terminal):

- ``terminal``  raw-mode I/O, alt-screen, SIGWINCH self-pipe.
- ``keys``      byte stream → typed key events (incremental parser).
- ``buffer``    multi-line text + cursor data structure.
- ``view``      renders a buffer into a viewport with scroll.
- ``editor``    the app: wires everything + save flow + quit confirm.
- ``coredump``  ``RLIMIT_CORE`` = 0 best-effort defense in depth.

See ``mm-crypt-cli/docs/tui-editor.md`` for the full design and threat model.
"""
