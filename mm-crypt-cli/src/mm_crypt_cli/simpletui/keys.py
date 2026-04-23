"""Parse a raw terminal byte stream into discrete key events.

The parser is a small state machine. In the NORMAL state we dispatch on the
first byte: ASCII controls become ``CTRL`` / ``ENTER`` / ``TAB`` / ``BACKSPACE``,
ESC starts a CSI/SS3 sequence, and UTF-8 multibyte sequences decode into
``CHAR``. When we see the bracketed-paste start marker ``CSI 200~`` we enter
PASTE state and accumulate text verbatim until the end marker ``CSI 201~``.

Partial sequences (half-arrived UTF-8, incomplete CSI, paste straddling two
reads) stay buffered across ``feed()`` calls.

Hardcoded xterm/VT100 conventions — no terminfo lookup. Every modern terminal
emits these same sequences for arrows, Home/End, Delete, and Page Up/Down.
"""

import unicodedata
from dataclasses import dataclass
from enum import StrEnum, auto


class KeyKind(StrEnum):
    """The kind of key event emitted by ``KeyParser``."""

    CHAR = auto()  # printable character — ``data`` holds it
    CTRL = auto()  # Ctrl+<letter> — ``data`` holds the letter, lowercase
    ENTER = auto()  # Enter/Return (CR or LF)
    TAB = auto()  # Tab (HT)
    BACKSPACE = auto()  # Backspace (BS or DEL)
    DELETE = auto()  # Delete (CSI 3~)
    ARROW_UP = auto()
    ARROW_DOWN = auto()
    ARROW_LEFT = auto()
    ARROW_RIGHT = auto()
    HOME = auto()
    END = auto()
    PAGE_UP = auto()
    PAGE_DOWN = auto()
    PASTE = auto()  # bracketed paste — ``data`` holds the pasted text


@dataclass(frozen=True, slots=True)
class KeyEvent:
    """A single key event parsed from the terminal byte stream."""

    kind: KeyKind  # What kind of event
    data: str = ""  # Payload for CHAR / CTRL / PASTE; empty otherwise


# CSI final bytes → key kind, for simple single-char sequences like CSI A.
_CSI_FINAL: dict[str, KeyKind] = {
    "A": KeyKind.ARROW_UP,
    "B": KeyKind.ARROW_DOWN,
    "C": KeyKind.ARROW_RIGHT,
    "D": KeyKind.ARROW_LEFT,
    "H": KeyKind.HOME,
    "F": KeyKind.END,
}

# CSI <n> ~ sequences (parameter before the ~) → key kind.
_CSI_TILDE: dict[str, KeyKind] = {
    "1": KeyKind.HOME,
    "7": KeyKind.HOME,
    "4": KeyKind.END,
    "8": KeyKind.END,
    "3": KeyKind.DELETE,
    "5": KeyKind.PAGE_UP,
    "6": KeyKind.PAGE_DOWN,
}

_PASTE_END = b"\x1b[201~"  # Bracketed-paste end marker (start marker is matched inline in _try_parse_csi).


class KeyParser:
    """Incremental byte → ``KeyEvent`` parser.

    Stateful: partial sequences (UTF-8 mid-codepoint, CSI without final byte,
    paste without end marker) remain buffered until ``feed()`` is called with
    enough additional bytes to complete them.
    """

    def __init__(self) -> None:
        """Start with an empty buffer and no active paste."""
        self._buf: bytearray = bytearray()  # bytes not yet consumed by a complete event
        self._paste: list[str] | None = None  # active paste text chunks; None = not in paste mode

    def feed(self, chunk: bytes) -> list[KeyEvent]:
        """Feed raw bytes from the terminal; return all events that can be completed."""
        self._buf.extend(chunk)
        events: list[KeyEvent] = []
        while self._buf:
            consumed = self._try_parse_one(events)
            if consumed == 0:
                break  # need more bytes
            del self._buf[:consumed]
        return events

    def _try_parse_one(self, events: list[KeyEvent]) -> int:
        """Try to emit one event from the head of the buffer. Return bytes consumed (0 = wait)."""
        # Paste mode absorbs bytes verbatim until the end marker.
        if self._paste is not None:
            return self._try_parse_paste(events, self._paste)
        b = self._buf[0]
        if b == 0x1B:
            return self._try_parse_escape(events)
        if b == 0x09:
            events.append(KeyEvent(kind=KeyKind.TAB))
            return 1
        if b in (0x0A, 0x0D):
            events.append(KeyEvent(kind=KeyKind.ENTER))
            return 1
        if b in (0x08, 0x7F):
            events.append(KeyEvent(kind=KeyKind.BACKSPACE))
            return 1
        if 0x01 <= b <= 0x1A:
            # Remaining C0 controls are Ctrl+<letter>. (TAB/LF/CR/BS already handled above.)
            events.append(KeyEvent(kind=KeyKind.CTRL, data=chr(b + 0x60)))
            return 1
        if b < 0x20:
            return 1  # unmapped C0 control — drop
        if b < 0x80:
            events.append(KeyEvent(kind=KeyKind.CHAR, data=chr(b)))
            return 1
        return self._try_parse_utf8(events)

    def _try_parse_utf8(self, events: list[KeyEvent]) -> int:
        """Consume one UTF-8 codepoint from the head of the buffer."""
        b = self._buf[0]
        if b & 0xE0 == 0xC0:
            n = 2
        elif b & 0xF0 == 0xE0:
            n = 3
        elif b & 0xF8 == 0xF0:
            n = 4
        else:
            return 1  # invalid UTF-8 start byte — drop
        if len(self._buf) < n:
            return 0
        try:
            ch = bytes(self._buf[:n]).decode("utf-8")
        except UnicodeDecodeError:
            return 1
        # Non-character controls slipping through in the high-codepoint range — drop.
        if len(ch) == 1 and unicodedata.category(ch).startswith("C"):
            return n
        events.append(KeyEvent(kind=KeyKind.CHAR, data=ch))
        return n

    def _try_parse_escape(self, events: list[KeyEvent]) -> int:
        """ESC seen — decide if it starts a CSI/SS3 or should be dropped."""
        if len(self._buf) < 2:
            return 0  # wait for the next byte to disambiguate
        second = self._buf[1]
        if second == 0x5B:  # '['
            return self._try_parse_csi(events)
        if second == 0x4F:  # 'O'
            return self._try_parse_ss3(events)
        # ESC + other byte — drop the ESC and let the next iteration handle the byte.
        return 1

    def _try_parse_csi(self, events: list[KeyEvent]) -> int:
        """Parse ``ESC [ <params> <intermediate> <final>`` per ECMA-48 CSI."""
        # Parameter bytes are 0x30-0x3F; intermediate bytes are 0x20-0x2F; final is 0x40-0x7E.
        i = 2
        while i < len(self._buf) and 0x30 <= self._buf[i] <= 0x3F:
            i += 1
        while i < len(self._buf) and 0x20 <= self._buf[i] <= 0x2F:
            i += 1
        if i >= len(self._buf):
            return 0
        final_byte = self._buf[i]
        if final_byte < 0x40 or final_byte > 0x7E:
            return i + 1  # malformed — drop the whole sequence
        params = bytes(self._buf[2:i]).decode("ascii", errors="replace")
        final = chr(final_byte)
        consumed = i + 1
        # Bracketed paste start marker: switch into paste mode; caller will drive paste parsing.
        if final == "~" and params == "200":
            self._paste = []
            return consumed
        if final == "~":
            kind = _CSI_TILDE.get(params.split(";")[0])
            if kind is not None:
                events.append(KeyEvent(kind=kind))
            return consumed
        if final in _CSI_FINAL:
            events.append(KeyEvent(kind=_CSI_FINAL[final]))
            return consumed
        return consumed  # unknown CSI — drop

    def _try_parse_ss3(self, events: list[KeyEvent]) -> int:
        """Parse ``ESC O X`` single-character SS3 sequences (xterm keypad/arrow variant)."""
        if len(self._buf) < 3:
            return 0
        final = chr(self._buf[2])
        if final in _CSI_FINAL:
            events.append(KeyEvent(kind=_CSI_FINAL[final]))
        return 3

    def _try_parse_paste(self, events: list[KeyEvent], paste: list[str]) -> int:
        """Absorb bytes until the bracketed-paste end marker; then emit one PASTE event."""
        idx = self._buf.find(_PASTE_END)
        if idx == -1:
            # Keep enough trailing bytes unconsumed to detect the end marker if it straddles.
            keep = len(_PASTE_END) - 1
            if len(self._buf) <= keep:
                return 0
            take = len(self._buf) - keep
            paste.append(bytes(self._buf[:take]).decode("utf-8", errors="replace"))
            return take
        if idx > 0:
            paste.append(bytes(self._buf[:idx]).decode("utf-8", errors="replace"))
        text = "".join(paste)
        self._paste = None
        events.append(KeyEvent(kind=KeyKind.PASTE, data=text))
        return idx + len(_PASTE_END)
