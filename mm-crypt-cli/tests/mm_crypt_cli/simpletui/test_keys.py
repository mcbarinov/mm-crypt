"""Tests for the raw-terminal byte → `KeyEvent` parser."""

import pytest
from mm_crypt_cli.simpletui.keys import KeyEvent, KeyKind, KeyParser


def _feed(data: bytes) -> list[KeyEvent]:
    """Build a fresh parser and feed `data` as a single chunk."""
    return KeyParser().feed(data)


class TestAsciiAndControls:
    """Printable ASCII, TAB, ENTER, BACKSPACE, and Ctrl+<letter>."""

    def test_printable_char(self):
        """A printable 7-bit byte emits a single CHAR with the literal character."""
        [ev] = _feed(b"a")
        assert ev == KeyEvent(KeyKind.CHAR, "a")

    def test_tab(self):
        """0x09 → TAB."""
        [ev] = _feed(b"\x09")
        assert ev.kind == KeyKind.TAB

    def test_enter_lf(self):
        """0x0A → ENTER."""
        [ev] = _feed(b"\n")
        assert ev.kind == KeyKind.ENTER

    def test_enter_cr(self):
        """0x0D → ENTER."""
        [ev] = _feed(b"\r")
        assert ev.kind == KeyKind.ENTER

    def test_backspace_bs(self):
        """0x08 → BACKSPACE."""
        [ev] = _feed(b"\x08")
        assert ev.kind == KeyKind.BACKSPACE

    def test_backspace_del(self):
        """0x7F (xterm default for Backspace) → BACKSPACE."""
        [ev] = _feed(b"\x7f")
        assert ev.kind == KeyKind.BACKSPACE

    @pytest.mark.parametrize(
        ("byte", "letter"),
        [(0x01, "a"), (0x03, "c"), (0x13, "s"), (0x1A, "z")],
    )
    def test_ctrl_letter(self, byte, letter):
        """Remaining C0 controls map to `CTRL` + lowercase letter."""
        [ev] = _feed(bytes([byte]))
        assert ev == KeyEvent(KeyKind.CTRL, letter)

    def test_unmapped_c0_dropped(self):
        """C0 bytes above 0x1A and not part of an escape are dropped."""
        # 0x1C is FS — not mapped, not ESC. Feeding it alone yields no events.
        assert _feed(b"\x1c") == []


class TestCsi:
    """CSI escape sequences for arrows, Home/End, Delete, Page Up/Down."""

    @pytest.mark.parametrize(
        ("seq", "kind"),
        [
            (b"\x1b[A", KeyKind.ARROW_UP),
            (b"\x1b[B", KeyKind.ARROW_DOWN),
            (b"\x1b[C", KeyKind.ARROW_RIGHT),
            (b"\x1b[D", KeyKind.ARROW_LEFT),
            (b"\x1b[H", KeyKind.HOME),
            (b"\x1b[F", KeyKind.END),
        ],
    )
    def test_simple_final(self, seq, kind):
        """CSI <final> for the simple A/B/C/D/H/F map."""
        [ev] = _feed(seq)
        assert ev.kind == kind

    @pytest.mark.parametrize(
        ("seq", "kind"),
        [
            (b"\x1b[1~", KeyKind.HOME),
            (b"\x1b[7~", KeyKind.HOME),
            (b"\x1b[4~", KeyKind.END),
            (b"\x1b[8~", KeyKind.END),
            (b"\x1b[3~", KeyKind.DELETE),
            (b"\x1b[5~", KeyKind.PAGE_UP),
            (b"\x1b[6~", KeyKind.PAGE_DOWN),
        ],
    )
    def test_tilde_final(self, seq, kind):
        """CSI <param>~ maps Home/End/Delete/PageUp/PageDown per xterm."""
        [ev] = _feed(seq)
        assert ev.kind == kind

    def test_modifier_params_still_recognized(self):
        """CSI 3;5~ (Ctrl+Delete) still emits DELETE — modifier parameter is ignored."""
        [ev] = _feed(b"\x1b[3;5~")
        assert ev.kind == KeyKind.DELETE

    def test_unknown_csi_dropped(self):
        """Unknown CSI final byte yields no event but the sequence is consumed."""
        p = KeyParser()
        assert p.feed(b"\x1b[Z") == []
        # Following bytes parse normally — the buffer was drained.
        assert p.feed(b"x") == [KeyEvent(KeyKind.CHAR, "x")]

    def test_malformed_csi_dropped(self):
        """A non-final byte in final position is dropped; the parser recovers."""
        p = KeyParser()
        # 0x00 falls outside the CSI final range (0x40..0x7E).
        assert p.feed(b"\x1b[\x00") == []
        assert p.feed(b"x") == [KeyEvent(KeyKind.CHAR, "x")]


class TestSs3:
    """SS3 (`ESC O X`) encodes arrows / Home / End in xterm keypad mode."""

    @pytest.mark.parametrize(
        ("seq", "kind"),
        [
            (b"\x1bOA", KeyKind.ARROW_UP),
            (b"\x1bOB", KeyKind.ARROW_DOWN),
            (b"\x1bOC", KeyKind.ARROW_RIGHT),
            (b"\x1bOD", KeyKind.ARROW_LEFT),
            (b"\x1bOH", KeyKind.HOME),
            (b"\x1bOF", KeyKind.END),
        ],
    )
    def test_ss3_final(self, seq, kind):
        """SS3 final byte maps to the same KeyKind as the CSI equivalent."""
        [ev] = _feed(seq)
        assert ev.kind == kind

    def test_ss3_unknown_dropped(self):
        """Unknown SS3 final is consumed (3 bytes) but emits no event."""
        assert _feed(b"\x1bOZ") == []


class TestUtf8:
    """Multi-byte UTF-8 sequences produce exactly one CHAR event per codepoint."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("é".encode(), "é"),
            ("€".encode(), "€"),
            ("🔑".encode(), "🔑"),
        ],
    )
    def test_multibyte(self, raw, expected):
        """2/3/4-byte sequences decode to a single CHAR."""
        [ev] = _feed(raw)
        assert ev == KeyEvent(KeyKind.CHAR, expected)

    def test_split_across_feeds(self):
        """A codepoint split across two `feed()` calls emits exactly one event."""
        p = KeyParser()
        raw = "€".encode()  # 3 bytes: E2 82 AC
        assert p.feed(raw[:2]) == []
        [ev] = p.feed(raw[2:])
        assert ev == KeyEvent(KeyKind.CHAR, "€")

    def test_invalid_start_byte_dropped(self):
        """A standalone continuation byte (0x80..0xBF) is dropped."""
        p = KeyParser()
        assert p.feed(b"\x80") == []
        assert p.feed(b"x") == [KeyEvent(KeyKind.CHAR, "x")]


class TestCsiBuffering:
    """Partial CSI sequences remain buffered until enough bytes arrive."""

    def test_csi_split_across_feeds(self):
        """`ESC [ A` arriving in three chunks still emits one ARROW_UP."""
        p = KeyParser()
        assert p.feed(b"\x1b") == []
        assert p.feed(b"[") == []
        [ev] = p.feed(b"A")
        assert ev.kind == KeyKind.ARROW_UP


class TestBracketedPaste:
    """`CSI 200~` … `CSI 201~` frames a PASTE event."""

    def test_single_feed(self):
        """A complete paste arriving in one feed emits one PASTE event."""
        [ev] = _feed(b"\x1b[200~hello\x1b[201~")
        assert ev == KeyEvent(KeyKind.PASTE, "hello")

    def test_straddling_payload(self):
        """Paste payload split across feeds still emits one PASTE event."""
        p = KeyParser()
        assert p.feed(b"\x1b[200~hel") == []
        assert p.feed(b"lo\x1b[201~") == [KeyEvent(KeyKind.PASTE, "hello")]

    def test_straddling_end_marker(self):
        """Parser keeps enough trailing bytes to detect an end marker that straddles feeds."""
        p = KeyParser()
        # The end-marker prefix "\x1b[20" must be held back — not emitted yet.
        assert p.feed(b"\x1b[200~hello\x1b[20") == []
        [ev] = p.feed(b"1~")
        assert ev == KeyEvent(KeyKind.PASTE, "hello")

    def test_paste_then_next_key(self):
        """After the end marker, subsequent bytes parse normally."""
        events = _feed(b"\x1b[200~x\x1b[201~y")
        assert events == [KeyEvent(KeyKind.PASTE, "x"), KeyEvent(KeyKind.CHAR, "y")]
