"""Raw-mode terminal session built on termios + hardcoded ANSI escape sequences.

This is the low-level I/O layer used by the editor. It owns stdin/stdout,
puts the terminal into cbreak + no-echo + no-IXON mode so Ctrl+S/Ctrl+Q reach
us as plain bytes, enters the alternate screen, enables bracketed paste, and
turns SIGWINCH into a select-wakeup via a self-pipe.

Zero terminfo lookups, zero ncurses, zero environment variables consulted.
Every byte we write to the terminal is a hardcoded xterm/VT100 control
sequence that every modern terminal emulator (iTerm2, Terminal.app, Alacritty,
kitty, Ghostty, gnome-terminal, konsole, tmux, screen) implements.

Security rationale: see ``docs/tui-editor.md`` — we avoid every TUI library /
terminal-DB dependency specifically to eliminate the class of "env var causes
library to write buffer content to disk" risks.
"""

import contextlib
import fcntl
import os
import select
import signal
import struct
import sys
import termios
import tty
from types import FrameType, TracebackType
from typing import Self

# Every control sequence we emit lives in this block so a grep locates them all.
_ALT_SCREEN_ON = "\x1b[?1049h"
_ALT_SCREEN_OFF = "\x1b[?1049l"
_CURSOR_HIDE = "\x1b[?25l"
_CURSOR_SHOW = "\x1b[?25h"
_CLEAR_SCREEN = "\x1b[2J"
_CURSOR_HOME = "\x1b[H"
_CLEAR_LINE_TO_EOL = "\x1b[K"
_BRACKETED_PASTE_ON = "\x1b[?2004h"
_BRACKETED_PASTE_OFF = "\x1b[?2004l"


class Terminal:
    """Context-managed raw-mode terminal session.

    Enters raw mode + alt screen + bracketed paste on ``__enter__``; fully
    restores the caller's terminal state on ``__exit__`` (even on exceptions).
    Leaving the shell in raw mode would make it unusable, so the restore path
    is best-effort unconditional.
    """

    def __init__(self) -> None:
        """Capture stdin/stdout fds; state is acquired lazily on ``__enter__``."""
        self._in_fd = sys.stdin.fileno()  # tty file descriptor for input
        self._out_fd = sys.stdout.fileno()  # tty file descriptor for output
        self._saved_attrs: list[int | list[bytes | int]] | None = None  # termios state to restore on exit
        self._wakeup_r = -1  # read end of SIGWINCH self-pipe (-1 = not created)
        self._wakeup_w = -1  # write end of SIGWINCH self-pipe (-1 = not created)
        self._prev_wakeup_fd = -1  # signal.set_wakeup_fd value to restore (meaningful only if _installed_wakeup_fd)
        self._installed_wakeup_fd = False  # whether we successfully replaced signal.set_wakeup_fd
        self._installed_sigwinch = False  # whether we replaced the SIGWINCH handler

    def __enter__(self) -> Self:
        """Put the terminal into editor mode and install the resize handler.

        Exception-safe: if any step raises after termios has already been modified,
        we unwind whatever partial state was installed before re-raising, so the
        caller's shell never ends up stranded in raw mode.
        """
        if not (os.isatty(self._in_fd) and os.isatty(self._out_fd)):
            raise RuntimeError("Terminal requires stdin and stdout to be a TTY.")
        try:
            # Snapshot full termios state so we can put the shell back exactly as we found it.
            self._saved_attrs = termios.tcgetattr(self._in_fd)
            # cbreak: one char at a time, no echo, no canonical mode. ISIG stays on so
            # Ctrl+C still raises KeyboardInterrupt at the Python level.
            tty.setcbreak(self._in_fd, termios.TCSANOW)
            # Disable input flow-control (IXON) so Ctrl+S/Ctrl+Q arrive as bytes 0x13/0x11
            # instead of freezing/resuming terminal output.
            attrs = termios.tcgetattr(self._in_fd)
            attrs[0] &= ~termios.IXON  # iflag
            termios.tcsetattr(self._in_fd, termios.TCSANOW, attrs)
            # Self-pipe for SIGWINCH: Python writes the signal number to this fd when the
            # signal fires, which wakes up our select() loop so we can redraw at the new size.
            self._wakeup_r, self._wakeup_w = os.pipe()
            for fd in (self._wakeup_r, self._wakeup_w):
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            self._prev_wakeup_fd = signal.set_wakeup_fd(self._wakeup_w)
            self._installed_wakeup_fd = True
            # The handler itself does nothing — the side effect we care about (writing to
            # the wakeup fd) is done by the interpreter before our handler is called.
            signal.signal(signal.SIGWINCH, _noop_signal_handler)
            self._installed_sigwinch = True
            _write_all(self._out_fd, _ALT_SCREEN_ON + _CURSOR_HIDE + _BRACKETED_PASTE_ON + _CLEAR_SCREEN + _CURSOR_HOME)
        except BaseException:
            self._teardown()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Restore terminal state. Always runs, even on exceptions."""
        del exc_type, exc, tb
        self._teardown()

    def _teardown(self) -> None:
        """Undo whatever __enter__ managed to install. Safe to call on partial setup."""
        # Best-effort writes; if the terminal is already gone there's nothing to do.
        with contextlib.suppress(OSError):
            _write_all(self._out_fd, _BRACKETED_PASTE_OFF + _CURSOR_SHOW + _ALT_SCREEN_OFF)
        if self._installed_sigwinch:
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)
            self._installed_sigwinch = False
        # Restore wakeup fd only if we successfully replaced it; otherwise the
        # caller's wakeup fd (whatever it was) has not been touched by us.
        if self._installed_wakeup_fd:
            signal.set_wakeup_fd(self._prev_wakeup_fd)
            self._installed_wakeup_fd = False
            self._prev_wakeup_fd = -1
        if self._wakeup_r != -1:
            os.close(self._wakeup_r)
            self._wakeup_r = -1
        if self._wakeup_w != -1:
            os.close(self._wakeup_w)
            self._wakeup_w = -1
        if self._saved_attrs is not None:
            termios.tcsetattr(self._in_fd, termios.TCSANOW, self._saved_attrs)
            self._saved_attrs = None

    def size(self) -> tuple[int, int]:
        """Return (rows, cols) of the controlling TTY via TIOCGWINSZ.

        Falls back to (24, 80) if the ioctl reports zeros (some test harnesses).
        """
        packed = fcntl.ioctl(self._out_fd, termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        return (rows or 24, cols or 80)

    def read_bytes(self) -> bytes:
        """Block until input (or a resize) arrives; return raw bytes from stdin.

        Returns an empty ``bytes`` if only a resize signal woke us up — the caller
        is expected to re-query ``size()`` and redraw.
        """
        while True:
            try:
                readable, _, _ = select.select([self._in_fd, self._wakeup_r], [], [])
            except InterruptedError:
                continue
            resized = False
            if self._wakeup_r in readable:
                # Drain the self-pipe so the next select blocks cleanly.
                with contextlib.suppress(BlockingIOError):
                    os.read(self._wakeup_r, 4096)
                resized = True
            if self._in_fd in readable:
                chunk = os.read(self._in_fd, 4096)
                if chunk:
                    return chunk
            if resized:
                return b""

    def write(self, data: str) -> None:
        """Write a UTF-8 chunk (ANSI escapes + content) to stdout."""
        _write_all(self._out_fd, data)

    def clear_screen(self) -> None:
        """Erase the entire screen and home the cursor."""
        _write_all(self._out_fd, _CLEAR_SCREEN + _CURSOR_HOME)

    def move_cursor(self, row: int, col: int) -> None:
        """Position the cursor at (row, col), 1-based."""
        _write_all(self._out_fd, f"\x1b[{row};{col}H")

    def clear_line_to_eol(self) -> None:
        """Erase from the cursor to the end of the current line."""
        _write_all(self._out_fd, _CLEAR_LINE_TO_EOL)

    def hide_cursor(self) -> None:
        """Hide the cursor (useful while redrawing to avoid flicker)."""
        _write_all(self._out_fd, _CURSOR_HIDE)

    def show_cursor(self) -> None:
        """Show the cursor."""
        _write_all(self._out_fd, _CURSOR_SHOW)


def _write_all(fd: int, data: str) -> None:
    """Write the full UTF-8-encoded string, looping over short writes."""
    payload = data.encode("utf-8")
    while payload:
        n = os.write(fd, payload)
        payload = payload[n:]


def _noop_signal_handler(signum: int, frame: FrameType | None) -> None:
    """SIGWINCH handler — Python's signal module delivers the wakeup byte for us."""
    del signum, frame
