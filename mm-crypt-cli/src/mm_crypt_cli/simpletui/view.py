"""Render a ``TextBuffer`` into a rectangular terminal viewport.

The view is stateful: it owns the vertical (``top``) and horizontal (``left``)
scroll offsets and adjusts them on each ``render()`` so the cursor stays
inside the viewport. Layout is fixed: the bottom row is reserved for the
status line; the rows above it show buffer content.

Wide / combining characters: cell widths are computed via
``unicodedata.east_asian_width``. C0 control bytes and DEL inside the buffer
are rendered with ``^X`` caret notation — this is also our defense against
ANSI escape injection from file content. A buffer containing literal escape
bytes never reaches the terminal as raw escapes; the user sees ``^[``.

No soft wrap: lines longer than the viewport scroll horizontally to keep the
cursor visible. This keeps the implementation small and explicit.
"""

import unicodedata

from mm_crypt_cli.simpletui.buffer import TextBuffer
from mm_crypt_cli.simpletui.terminal import Terminal

_REVERSE_VIDEO = "\x1b[7m"
_ATTR_RESET = "\x1b[0m"


def render_char(ch: str) -> tuple[str, int]:
    r"""Return ``(text-to-write, cells-occupied)`` for one logical character.

    Control characters and DEL render as caret notation (e.g. ``\x1b`` → ``"^["``);
    that is both more readable and safe against terminal-escape injection from
    the file contents we are editing. East-Asian wide characters take 2 cells;
    combining characters take 0.
    """
    cp = ord(ch)
    if cp < 0x20:
        return (f"^{chr(cp + 0x40)}", 2)
    if cp == 0x7F:
        return ("^?", 2)
    if unicodedata.combining(ch):
        return (ch, 0)
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return (ch, 2)
    return (ch, 1)


def cursor_cell(line: str, col: int) -> int:
    """Return the cell-column corresponding to character column ``col`` in ``line``."""
    cell = 0
    for i, ch in enumerate(line):
        if i >= col:
            break
        _, w = render_char(ch)
        cell += w
    return cell


class TextAreaView:
    """Stateful renderer: viewport size + scroll offsets + draw routine."""

    def __init__(self) -> None:
        """Start with an unset viewport; ``set_viewport`` must be called before ``render``."""
        self._top = 0  # first visible buffer row
        self._left = 0  # first visible cell column
        self._rows = 0  # viewport row count (incl. status line)
        self._cols = 0  # viewport column count

    def set_viewport(self, rows: int, cols: int) -> None:
        """Update viewport dimensions; call after each terminal resize."""
        self._rows = rows
        self._cols = cols

    @property
    def content_rows(self) -> int:
        """Rows available for buffer content (viewport minus the status line)."""
        return max(0, self._rows - 1)

    def render(self, term: Terminal, buffer: TextBuffer, status: str) -> None:
        """Repaint the entire viewport: text rows, status line, cursor."""
        if self._rows < 1 or self._cols < 1:
            return  # degenerate terminal size — nothing to draw safely
        content_rows = self.content_rows
        self._scroll_to_cursor(buffer, content_rows)
        term.hide_cursor()
        for i in range(content_rows):
            term.move_cursor(i + 1, 1)
            row_idx = self._top + i
            if row_idx < buffer.line_count:
                self._draw_line(term, buffer.line(row_idx))
            else:
                term.clear_line_to_eol()
        term.move_cursor(self._rows, 1)
        self._draw_status(term, status)
        # Position the real cursor over the buffer cursor's visual cell.
        vrow = buffer.row - self._top
        vcol = cursor_cell(buffer.line(buffer.row), buffer.col) - self._left
        if 0 <= vrow < content_rows and 0 <= vcol < self._cols:
            term.move_cursor(vrow + 1, vcol + 1)
            term.show_cursor()

    def _scroll_to_cursor(self, buffer: TextBuffer, content_rows: int) -> None:
        """Adjust ``_top`` and ``_left`` so the cursor lands inside the viewport."""
        if content_rows <= 0:
            return
        if buffer.row < self._top:
            self._top = buffer.row
        elif buffer.row >= self._top + content_rows:
            self._top = buffer.row - content_rows + 1
        ccell = cursor_cell(buffer.line(buffer.row), buffer.col)
        if ccell < self._left:
            self._left = ccell
        elif ccell >= self._left + self._cols:
            self._left = ccell - self._cols + 1
        self._left = max(self._left, 0)
        self._top = max(self._top, 0)

    def _draw_line(self, term: Terminal, line: str) -> None:
        """Paint one logical line into the current row, honoring horizontal scroll."""
        cell = 0
        out: list[str] = []
        for ch in line:
            text, w = render_char(ch)
            if cell + w <= self._left:
                # Entirely to the left of the visible window.
                cell += w
                continue
            if cell >= self._left + self._cols:
                break
            if cell < self._left < cell + w:
                # Wide char straddling the left edge — show the visible right half as spaces.
                pad = (cell + w) - self._left
                out.append(" " * pad)
                cell += w
                continue
            if cell + w > self._left + self._cols:
                # Wide char straddling the right edge — drop it (would overflow).
                break
            out.append(text)
            cell += w
        term.write("".join(out))
        term.clear_line_to_eol()

    def _draw_status(self, term: Terminal, status: str) -> None:
        """Paint the status line in reverse video, padded to the full width."""
        # We control status content (modified flag, path, prompts) — assume narrow chars.
        visible = status[: self._cols]
        padding = " " * max(0, self._cols - len(visible))
        term.write(_REVERSE_VIDEO + visible + padding + _ATTR_RESET)
