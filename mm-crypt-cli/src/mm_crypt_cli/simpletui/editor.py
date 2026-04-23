"""Interactive editor for one scrypt-encrypted text document.

Wires the four primitives in this package — ``Terminal`` (raw I/O),
``KeyParser`` (byte stream → events), ``TextBuffer`` (text + cursor), and
``TextAreaView`` (renderer) — into an event loop. Owns the target path,
password, and modified state.

On Ctrl+S the buffer is encrypted with ``mm_crypt.scrypt.encrypt_bytes`` and
the resulting ciphertext atomically replaces the file via tmp + rename. On
Ctrl+Q the editor either exits (clean buffer) or shows an inline confirm
prompt in the status row (modified buffer).

Security: plaintext never touches disk via this module. ``_write_encrypted``
encrypts in memory first; the tmp file only ever holds ciphertext. See
``docs/tui-editor.md`` for the full save-flow and threat model.
"""

import contextlib
import os
import tempfile
import time
from pathlib import Path

from mm_crypt import scrypt

from mm_crypt_cli.simpletui.buffer import TextBuffer
from mm_crypt_cli.simpletui.keys import KeyEvent, KeyKind, KeyParser
from mm_crypt_cli.simpletui.terminal import Terminal
from mm_crypt_cli.simpletui.view import TextAreaView

_FLASH_DEFAULT = 1.5  # seconds a transient status message stays visible
_FLASH_ERROR = 5.0  # transient status duration for error messages


class EditorApp:
    """Single-document editor session."""

    def __init__(self, *, path: Path, password: str, initial_text: str, readonly: bool) -> None:
        """Build with the resolved path and the password held in memory.

        Args:
            path: Target encrypted file. May not yet exist for a new document.
            password: Used to re-encrypt the buffer on every save.
            initial_text: Plaintext loaded by the caller (empty for a new file).
            readonly: True opens in view-only mode; save and edits are disabled.

        """
        self._path = path  # encrypted file on disk (target of save)
        self._password = password  # held in memory for the session's lifetime
        self._readonly = readonly  # opened with --view
        self._buffer = TextBuffer(initial_text)  # the editable text + cursor
        self._view = TextAreaView()  # renderer (owns scroll offsets)
        self._saved_text = initial_text  # last persisted contents — drives modified flag
        self._flash_text = ""  # transient status text overriding the default
        self._flash_until = 0.0  # monotonic deadline at which flash text expires

    def run(self) -> None:
        """Open the terminal and run the event loop until the user quits."""
        with Terminal() as term:
            self._event_loop(term)

    def _event_loop(self, term: Terminal) -> None:
        """Read input, dispatch events, redraw — until ``_handle_event`` returns False."""
        parser = KeyParser()
        self._render(term)
        while True:
            chunk = term.read_bytes()
            if not chunk:
                # Resize-only wakeup — viewport size changed; redraw.
                self._render(term)
                continue
            keep_running = True
            for ev in parser.feed(chunk):
                if not self._handle_event(ev, term):
                    keep_running = False
                    break
            if not keep_running:
                return
            self._render(term)

    def _render(self, term: Terminal) -> None:
        """Query terminal size, push it to the view, draw."""
        rows, cols = term.size()
        self._view.set_viewport(rows, cols)
        self._view.render(term, self._buffer, self._status_text())

    def _status_text(self) -> str:
        """Compose the status-bar text — flash message overrides default."""
        if self._flash_text and time.monotonic() < self._flash_until:
            return self._flash_text
        flag = "*" if self._is_modified() else " "
        tag = "  [read-only]" if self._readonly else ""
        return f"{flag} {self._path}{tag}    ^S save   ^Q quit"

    def _is_modified(self) -> bool:
        """Return True if the buffer diverges from the last saved text."""
        return self._buffer.text != self._saved_text

    def _flash(self, text: str, duration: float = _FLASH_DEFAULT) -> None:
        """Show ``text`` in the status bar for ``duration`` seconds."""
        self._flash_text = text
        self._flash_until = time.monotonic() + duration

    def _handle_event(self, ev: KeyEvent, term: Terminal) -> bool:
        """Dispatch one key event. Return False to exit the event loop."""
        if ev.kind == KeyKind.CTRL and ev.data == "s":
            self._action_save()
            return True
        if ev.kind == KeyKind.CTRL and ev.data == "q":
            return self._action_quit(term)
        if ev.kind == KeyKind.CTRL and ev.data == "c":
            # Ctrl+C is a common "get out" reflex; treat it like Ctrl+Q.
            return self._action_quit(term)
        if self._readonly:
            self._dispatch_navigation(ev)
            return True
        self._dispatch_edit(ev)
        return True

    def _dispatch_edit(self, ev: KeyEvent) -> None:
        """Apply a key event to the buffer (edit + navigation), in non-readonly mode."""
        if ev.kind in (KeyKind.CHAR, KeyKind.PASTE):
            self._buffer.insert_text(ev.data)
        elif ev.kind == KeyKind.ENTER:
            self._buffer.insert_newline()
        elif ev.kind == KeyKind.TAB:
            self._buffer.insert_text("\t")
        elif ev.kind == KeyKind.BACKSPACE:
            self._buffer.backspace()
        elif ev.kind == KeyKind.DELETE:
            self._buffer.delete()
        else:
            self._dispatch_navigation(ev)

    def _dispatch_navigation(self, ev: KeyEvent) -> None:
        """Apply navigation events (arrows, Home/End, Page Up/Down) to the buffer."""
        if ev.kind == KeyKind.ARROW_UP:
            self._buffer.move_up()
        elif ev.kind == KeyKind.ARROW_DOWN:
            self._buffer.move_down()
        elif ev.kind == KeyKind.ARROW_LEFT:
            self._buffer.move_left()
        elif ev.kind == KeyKind.ARROW_RIGHT:
            self._buffer.move_right()
        elif ev.kind == KeyKind.HOME:
            self._buffer.move_home()
        elif ev.kind == KeyKind.END:
            self._buffer.move_end()
        elif ev.kind == KeyKind.PAGE_UP:
            self._buffer.move_page_up(self._page_size())
        elif ev.kind == KeyKind.PAGE_DOWN:
            self._buffer.move_page_down(self._page_size())

    def _page_size(self) -> int:
        """Rows to jump per PageUp / PageDown — viewport content minus one line of overlap."""
        return max(1, self._view.content_rows - 1)

    def _action_save(self) -> None:
        """Ctrl+S: encrypt the buffer and atomically replace the file on disk."""
        if self._readonly:
            self._flash("Read-only mode — save disabled.")
            return
        text = self._buffer.text
        try:
            _write_encrypted(self._path, self._password, text)
        except OSError as exc:
            self._flash(f"Save failed: {exc}", duration=_FLASH_ERROR)
            return
        self._saved_text = text
        self._flash("Saved")

    def _action_quit(self, term: Terminal) -> bool:
        """Ctrl+Q: exit immediately if clean; otherwise inline-prompt save/discard/cancel."""
        if self._readonly or not self._is_modified():
            return False
        answer = self._confirm_quit(term)
        if answer == "discard":
            return False
        if answer == "save":
            self._action_save()
            # If the save failed the buffer is still modified — stay in the editor.
            return self._is_modified()
        return True  # cancel

    def _confirm_quit(self, term: Terminal) -> str:
        """Block on a y/n/c keystroke shown inline in the status bar."""
        parser = KeyParser()
        prompt = "Unsaved changes. Save?  [y]es   [n]o (discard)   [c]ancel"
        while True:
            rows, cols = term.size()
            self._view.set_viewport(rows, cols)
            self._view.render(term, self._buffer, prompt)
            chunk = term.read_bytes()
            if not chunk:
                continue
            for ev in parser.feed(chunk):
                if ev.kind == KeyKind.CHAR and ev.data in ("y", "Y"):
                    return "save"
                if ev.kind == KeyKind.CHAR and ev.data in ("n", "N"):
                    return "discard"
                if ev.kind == KeyKind.CHAR and ev.data in ("c", "C"):
                    return "cancel"
                if ev.kind == KeyKind.CTRL and ev.data in ("c", "q"):
                    return "cancel"


def _write_encrypted(path: Path, password: str, text: str) -> None:
    """Encrypt ``text`` and atomically replace ``path``.

    Flow (only ciphertext ever lands on disk):

        1. Encrypt the buffer in memory — ``encrypt_bytes`` either returns the
           full scrypt blob or raises; nothing partial.
        2. ``tempfile.mkstemp`` creates a sibling tmp at mode 0600 in the same
           directory as the target so the subsequent rename is atomic on POSIX.
        3. Write the ciphertext, flush, fsync.
        4. ``Path.replace`` — single atomic rename syscall on POSIX.

    A crash anywhere in steps 2-4 leaves either the old ciphertext intact at
    ``path`` or a stray ciphertext tmp next to it; plaintext never touches disk.
    """
    ciphertext = scrypt.encrypt_bytes(data=text.encode("utf-8"), password=password)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
        tmp_path.replace(path)
    except BaseException:
        # Best-effort cleanup of the (always-ciphertext) tmp on any failure,
        # including KeyboardInterrupt. Leaving it is safe (encrypted, 0600) but messy.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
