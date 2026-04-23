"""Textual TUI editor for scrypt-encrypted text files.

The editor owns the password for the session: on Ctrl+S it re-encrypts the
current buffer and writes it back to disk atomically (tmp file + os.replace).
The outer CLI command prepares the initial plaintext (decrypting an existing
file or starting from empty for a new one) and launches this app.

Security invariant — plaintext never touches disk. The tmp file that save
writes to is **always ciphertext**: we encrypt the buffer in memory first,
then open the tmp file, then write the already-encrypted bytes, then atomic
rename. A crash at any point leaves either the old ciphertext intact or a
partial/complete ciphertext in the tmp sibling — never plaintext. The tmp
exists solely to guarantee crash-atomicity; without it, a partial in-place
write to the scrypt file would fail HMAC verification on next read and the
document would be permanently unrecoverable. See docs/tui-editor.md for the
full security model.
"""

import contextlib
import os
import tempfile
from pathlib import Path
from typing import ClassVar

from mm_crypt import scrypt
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Label, Static, TextArea


class QuitConfirm(ModalScreen[str]):
    """Modal: unsaved changes — Save / Discard / Cancel."""

    DEFAULT_CSS = """
    QuitConfirm {
        align: center middle;
    }
    QuitConfirm > Vertical {
        width: 60;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    QuitConfirm Label {
        width: 100%;
        content-align: center middle;
        padding-bottom: 1;
    }
    QuitConfirm Horizontal {
        height: auto;
        align: center middle;
    }
    QuitConfirm Button {
        margin: 0 1;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel")
    ]  # Esc = cancel quit

    def compose(self) -> ComposeResult:
        """Render the modal layout."""
        with Vertical():
            yield Label("Unsaved changes. Save before quitting?")
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Discard", id="discard", variant="error")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the chosen action id."""
        self.dismiss(event.button.id or "cancel")

    def action_cancel(self) -> None:
        """Esc dismisses the modal without quitting."""
        self.dismiss("cancel")


class EditorApp(App[None]):
    """Textual editor for a single scrypt-encrypted text document."""

    CSS = """
    Screen {
        layout: vertical;
    }
    TextArea {
        height: 1fr;
    }
    #status {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text;
        padding: 0 1;
    }
    """

    # priority=True ensures the bindings fire even while TextArea has focus.
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    def __init__(self, *, path: Path, password: str, initial_text: str, readonly: bool) -> None:
        """Build the editor app.

        Args:
            path: Target file path on disk (may or may not exist yet).
            password: Passphrase used for both load (already done by caller) and save.
            initial_text: Current plaintext contents — "" for a brand-new file.
            readonly: If True, disables save and opens the buffer in read-only mode.

        """
        super().__init__()
        self._path = path  # Encrypted file on disk (target of save)
        self._password = password  # Kept in memory for re-encryption on save
        self._initial_text = initial_text  # Plaintext loaded at launch
        self._readonly = readonly  # True when opened with --view
        self._saved_text = initial_text  # Last-persisted text; drives modified-flag

    def compose(self) -> ComposeResult:
        """Render the main layout: header, editor, status bar, footer."""
        yield Header(show_clock=False)
        yield TextArea(self._initial_text, read_only=self._readonly, id="editor", soft_wrap=True)
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Focus the editor and paint the initial status bar."""
        self.title = self._path.name
        self.sub_title = "read-only" if self._readonly else ""
        editor = self.query_one("#editor", TextArea)
        editor.focus()
        self._refresh_status()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Repaint the modified flag whenever the buffer changes."""
        del event  # unused
        self._refresh_status()

    def _current_text(self) -> str:
        """Return the current buffer contents."""
        return self.query_one("#editor", TextArea).text

    def _is_modified(self) -> bool:
        """Return True if the buffer diverges from the last saved state."""
        return self._current_text() != self._saved_text

    def _refresh_status(self) -> None:
        """Update the status bar with modified flag and path."""
        flag = "*" if self._is_modified() else " "
        suffix = "  [read-only]" if self._readonly else ""
        self.query_one("#status", Static).update(f"{flag} {self._path}{suffix}")

    def action_save(self) -> None:
        """Ctrl+S: re-encrypt the buffer and write atomically to disk."""
        if self._readonly:
            self.notify("Read-only mode — save disabled.", severity="warning")
            return
        text = self._current_text()
        try:
            _write_encrypted(self._path, self._password, text)
        except OSError as exc:
            self.notify(f"Save failed: {exc}", severity="error", timeout=5.0)
            return
        self._saved_text = text
        self._refresh_status()
        self.notify("Saved", timeout=1.5)

    def action_quit(self) -> None:  # type: ignore[override]
        """Ctrl+Q: exit, prompting if there are unsaved changes."""
        if self._readonly or not self._is_modified():
            self.exit()
            return
        self.push_screen(QuitConfirm(), self._handle_quit_answer)

    def _handle_quit_answer(self, answer: str | None) -> None:
        """Handle the QuitConfirm modal's answer."""
        if answer == "discard":
            self.exit()
            return
        if answer == "save":
            self.action_save()
            # If save failed the buffer is still modified — stay in the app.
            if not self._is_modified():
                self.exit()


def _write_encrypted(path: Path, password: str, text: str) -> None:
    """Encrypt `text` and atomically replace `path` with the resulting ciphertext.

    Flow (ciphertext-only on disk, at every step):

        1. Encrypt the buffer in memory — `encrypt_bytes` either returns the
           full scrypt blob or raises; nothing is partial.
        2. Create a sibling tmp file via `tempfile.mkstemp` — mode 0600, same
           directory as the target so the subsequent rename is atomic on POSIX.
        3. Write the (already encrypted) bytes into the tmp, flush, fsync.
        4. `tmp_path.replace(path)` — single atomic syscall on POSIX.

    A crash anywhere in steps 2-4 leaves either the old ciphertext intact or
    a stray ciphertext tmp next to it; plaintext never lands on disk. See
    ``docs/tui-editor.md`` for the full security model.
    """
    ciphertext = scrypt.encrypt_bytes(data=text.encode("utf-8"), password=password)
    # Same directory as target → atomic rename; mkstemp default mode is 0600.
    # Hidden dot-prefix + random suffix avoids clutter in `ls` and name collisions.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
        tmp_path.replace(path)
    except BaseException:
        # Best-effort cleanup of the (always-ciphertext) tmp on any failure —
        # including KeyboardInterrupt. Leaving it is safe (encrypted, 0600) but messy.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
