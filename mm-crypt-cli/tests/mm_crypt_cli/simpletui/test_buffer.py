"""Tests for the in-memory `TextBuffer` underlying the TUI editor."""

from mm_crypt_cli.simpletui.buffer import TextBuffer


class TestInit:
    """Construction normalizes text into a list of lines with cursor at (0, 0)."""

    def test_empty(self):
        """An empty string yields one empty line."""
        b = TextBuffer()
        assert b.line_count == 1
        assert b.line(0) == ""
        assert (b.row, b.col) == (0, 0)

    def test_single_line(self):
        """A newline-free string stays as one line."""
        b = TextBuffer("abc")
        assert b.line_count == 1
        assert b.text == "abc"

    def test_multi_line(self):
        r"""Embedded ``\n`` splits into multiple lines."""
        b = TextBuffer("a\nb\nc")
        assert b.line_count == 3
        assert b.text == "a\nb\nc"

    def test_trailing_newline_yields_empty_last_line(self):
        r"""A trailing ``\n`` yields an empty last line (matches ``split('\n')`` semantics)."""
        b = TextBuffer("a\n")
        assert b.line_count == 2
        assert b.line(1) == ""


class TestInsertChar:
    """`insert_char` inserts one character and advances the cursor."""

    def test_into_empty(self):
        """Insert into an empty line moves the cursor to col 1."""
        b = TextBuffer()
        b.insert_char("x")
        assert b.text == "x"
        assert (b.row, b.col) == (0, 1)

    def test_middle_of_line(self):
        """Insert between existing chars; cursor lands after the new char."""
        b = TextBuffer("ab")
        b.move_right()  # cursor between a and b
        b.insert_char("X")
        assert b.text == "aXb"
        assert (b.row, b.col) == (0, 2)


class TestInsertText:
    """`insert_text` splices pasted, possibly multi-line strings."""

    def test_no_newline(self):
        """Newline-free text behaves like consecutive `insert_char` calls."""
        b = TextBuffer("ab")
        b.move_right()
        b.insert_text("XY")
        assert b.text == "aXYb"
        assert (b.row, b.col) == (0, 3)

    def test_single_newline(self):
        r"""A single ``\n`` splits the current line; cursor at start of the tail on row+1."""
        b = TextBuffer("ab")
        b.move_right()
        b.insert_text("X\nY")
        assert b.text == "aX\nYb"
        assert (b.row, b.col) == (1, 1)

    def test_multiple_newlines(self):
        r"""Intermediate parts become their own lines between the head and tail splice."""
        b = TextBuffer("ab")
        b.move_right()
        b.insert_text("P\nQ\nR")
        assert b.text == "aP\nQ\nRb"
        assert (b.row, b.col) == (2, 1)


class TestInsertNewline:
    """`insert_newline` splits the current line at the cursor."""

    def test_at_start(self):
        """Newline at col 0 pushes the current line down; cursor at (row+1, 0)."""
        b = TextBuffer("abc")
        b.insert_newline()
        assert b.text == "\nabc"
        assert (b.row, b.col) == (1, 0)

    def test_at_middle(self):
        """Newline in the middle splits the line; cursor at (row+1, 0)."""
        b = TextBuffer("abc")
        b.move_right()
        b.insert_newline()
        assert b.text == "a\nbc"
        assert (b.row, b.col) == (1, 0)

    def test_at_end(self):
        """Newline at EOL adds an empty line after; cursor on it."""
        b = TextBuffer("abc")
        b.move_end()
        b.insert_newline()
        assert b.text == "abc\n"
        assert (b.row, b.col) == (1, 0)


class TestBackspace:
    """`backspace` deletes the char before the cursor, joining at col 0."""

    def test_middle(self):
        """Backspace in the middle of a line deletes one char."""
        b = TextBuffer("abc")
        b.move_right()
        b.move_right()  # col=2
        b.backspace()
        assert b.text == "ac"
        assert (b.row, b.col) == (0, 1)

    def test_at_col_zero_joins_with_previous(self):
        """Backspace at (row>0, col=0) joins the current line with the previous one."""
        b = TextBuffer("ab\ncd")
        b.move_down()
        b.backspace()
        assert b.text == "abcd"
        assert (b.row, b.col) == (0, 2)

    def test_at_start_of_buffer_is_noop(self):
        """Backspace at (0, 0) does nothing and does not raise."""
        b = TextBuffer("a")
        b.backspace()
        assert b.text == "a"
        assert (b.row, b.col) == (0, 0)


class TestDelete:
    """`delete` removes the char under the cursor, joining with next at EOL."""

    def test_middle(self):
        """Delete at a middle column removes the char without moving the cursor."""
        b = TextBuffer("abc")
        b.move_right()
        b.delete()
        assert b.text == "ac"
        assert (b.row, b.col) == (0, 1)

    def test_at_end_of_line_joins_next(self):
        """Delete at EOL joins the current line with the next one."""
        b = TextBuffer("ab\ncd")
        b.move_end()
        b.delete()
        assert b.text == "abcd"
        assert (b.row, b.col) == (0, 2)

    def test_at_end_of_buffer_is_noop(self):
        """Delete at the end of the last line does nothing and does not raise."""
        b = TextBuffer("abc")
        b.move_end()
        b.delete()
        assert b.text == "abc"


class TestCursorMove:
    """Cursor navigation wraps across line boundaries and clamps column."""

    def test_move_left_wraps_to_previous_line(self):
        """At col 0 with row>0, move_left lands at end of previous line."""
        b = TextBuffer("ab\ncd")
        b.move_down()
        b.move_left()
        assert (b.row, b.col) == (0, 2)

    def test_move_left_at_start_is_noop(self):
        """At (0, 0), move_left does nothing."""
        b = TextBuffer("ab")
        b.move_left()
        assert (b.row, b.col) == (0, 0)

    def test_move_right_wraps_to_next_line(self):
        """At EOL, move_right lands at start of next line."""
        b = TextBuffer("ab\ncd")
        b.move_end()
        b.move_right()
        assert (b.row, b.col) == (1, 0)

    def test_move_right_at_end_is_noop(self):
        """At end of the last line, move_right does nothing."""
        b = TextBuffer("a")
        b.move_end()
        b.move_right()
        assert (b.row, b.col) == (0, 1)

    def test_move_up_clamps_column(self):
        """Moving up from a long line to a shorter one clamps col to the new line length."""
        b = TextBuffer("ab\nlonger")
        b.move_down()
        b.move_end()  # (1, 6)
        b.move_up()
        assert (b.row, b.col) == (0, 2)

    def test_move_down_clamps_column(self):
        """Moving down from a long line to a shorter one clamps col to the new line length."""
        b = TextBuffer("longer\nab")
        b.move_end()  # (0, 6)
        b.move_down()
        assert (b.row, b.col) == (1, 2)


class TestHomeEnd:
    """`move_home` / `move_end` snap the cursor to line boundaries."""

    def test_home(self):
        """`move_home` sets col to 0."""
        b = TextBuffer("abc")
        b.move_end()
        b.move_home()
        assert b.col == 0

    def test_end(self):
        """`move_end` sets col to the line length."""
        b = TextBuffer("abc")
        b.move_end()
        assert b.col == 3


class TestPageMove:
    """Page navigation jumps by a caller-supplied page size and clamps to buffer bounds."""

    def test_page_up_clamps_to_top(self):
        """`move_page_up` past the start lands at row 0."""
        b = TextBuffer("\n".join(str(i) for i in range(20)))
        b.move_page_down(10)
        b.move_page_up(100)
        assert b.row == 0

    def test_page_down_clamps_to_bottom(self):
        """`move_page_down` past the end lands at the last row."""
        b = TextBuffer("\n".join(str(i) for i in range(20)))
        b.move_page_down(100)
        assert b.row == 19
