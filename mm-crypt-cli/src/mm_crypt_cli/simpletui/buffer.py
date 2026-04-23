"""In-memory text buffer with a single cursor.

Pure data structure: lines are stored as a ``list[str]``, the cursor is a
``(row, col)`` index into that list. No rendering, no terminal I/O, no undo
history. The view layer reads ``lines`` / ``row`` / ``col`` to draw; the
editor layer translates key events into method calls.

Coordinates are in *characters* (Unicode codepoints), not display cells. The
view is responsible for converting char positions to cell positions when wide
characters are present.
"""


class TextBuffer:
    """Multi-line text buffer with a cursor and edit operations."""

    def __init__(self, text: str = "") -> None:
        """Initialize from a string. An empty string yields one empty line."""
        self._lines: list[str] = text.split("\n") if text else [""]  # one entry per logical line
        self._row = 0  # cursor row (0-based)
        self._col = 0  # cursor column (0-based, character index)

    @property
    def text(self) -> str:
        r"""Return the full buffer joined with ``\n``."""
        return "\n".join(self._lines)

    @property
    def row(self) -> int:
        """Current cursor row, 0-based."""
        return self._row

    @property
    def col(self) -> int:
        """Current cursor column, 0-based character index."""
        return self._col

    @property
    def line_count(self) -> int:
        """Number of logical lines in the buffer (always >= 1)."""
        return len(self._lines)

    def line(self, row: int) -> str:
        """Return the text of the given row."""
        return self._lines[row]

    def insert_char(self, ch: str) -> None:
        """Insert a single character at the cursor and advance one position."""
        line = self._lines[self._row]
        self._lines[self._row] = line[: self._col] + ch + line[self._col :]
        self._col += len(ch)

    def insert_text(self, text: str) -> None:
        r"""Insert arbitrary text (may contain ``\n``) at the cursor."""
        if "\n" not in text:
            self.insert_char(text)
            return
        parts = text.split("\n")
        current = self._lines[self._row]
        head = current[: self._col]
        tail = current[self._col :]
        # The first part appends to the current line up to head; the last part
        # prepends to tail; intermediate parts are inserted as full lines.
        self._lines[self._row] = head + parts[0]
        for i, mid in enumerate(parts[1:-1], start=1):
            self._lines.insert(self._row + i, mid)
        last_idx = self._row + len(parts) - 1
        self._lines.insert(last_idx, parts[-1] + tail)
        self._row = last_idx
        self._col = len(parts[-1])

    def insert_newline(self) -> None:
        """Split the current line at the cursor; cursor lands at the start of the new line."""
        line = self._lines[self._row]
        self._lines[self._row] = line[: self._col]
        self._lines.insert(self._row + 1, line[self._col :])
        self._row += 1
        self._col = 0

    def backspace(self) -> None:
        """Delete the character before the cursor; join with previous line at column 0."""
        if self._col > 0:
            line = self._lines[self._row]
            self._lines[self._row] = line[: self._col - 1] + line[self._col :]
            self._col -= 1
        elif self._row > 0:
            prev = self._lines[self._row - 1]
            curr = self._lines[self._row]
            self._col = len(prev)
            self._lines[self._row - 1] = prev + curr
            del self._lines[self._row]
            self._row -= 1

    def delete(self) -> None:
        """Delete the character under the cursor; join with next line at end-of-line."""
        line = self._lines[self._row]
        if self._col < len(line):
            self._lines[self._row] = line[: self._col] + line[self._col + 1 :]
        elif self._row < len(self._lines) - 1:
            self._lines[self._row] = line + self._lines[self._row + 1]
            del self._lines[self._row + 1]

    def move_left(self) -> None:
        """Move cursor one char left, wrapping to end of previous line."""
        if self._col > 0:
            self._col -= 1
        elif self._row > 0:
            self._row -= 1
            self._col = len(self._lines[self._row])

    def move_right(self) -> None:
        """Move cursor one char right, wrapping to start of next line."""
        line = self._lines[self._row]
        if self._col < len(line):
            self._col += 1
        elif self._row < len(self._lines) - 1:
            self._row += 1
            self._col = 0

    def move_up(self) -> None:
        """Move cursor up one line, clamping column to the new line's length."""
        if self._row > 0:
            self._row -= 1
            self._col = min(self._col, len(self._lines[self._row]))

    def move_down(self) -> None:
        """Move cursor down one line, clamping column to the new line's length."""
        if self._row < len(self._lines) - 1:
            self._row += 1
            self._col = min(self._col, len(self._lines[self._row]))

    def move_home(self) -> None:
        """Move cursor to the start of the current line."""
        self._col = 0

    def move_end(self) -> None:
        """Move cursor to the end of the current line."""
        self._col = len(self._lines[self._row])

    def move_page_up(self, page: int) -> None:
        """Move cursor up by ``page`` lines (clamped to the start of the buffer)."""
        self._row = max(0, self._row - page)
        self._col = min(self._col, len(self._lines[self._row]))

    def move_page_down(self, page: int) -> None:
        """Move cursor down by ``page`` lines (clamped to the end of the buffer)."""
        self._row = min(len(self._lines) - 1, self._row + page)
        self._col = min(self._col, len(self._lines[self._row]))
