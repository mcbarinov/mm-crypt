"""Shared pytest fixtures + a small in-process CLI test harness.

We replaced typer / click, so `typer.testing.CliRunner` is no longer available.
This module provides a drop-in stand-in: `CliRunner.invoke(app, args, input=...)`
returns a `Result` with `exit_code`, `stdout`, `stdout_bytes`, `stderr`, and
`output` (alias for stdout) — the subset of fields our tests rely on.

`app` here is any `Callable[[list[str]], int]` — in practice it's
`mm_crypt_cli.main.app`, which parses argv and returns the exit code.
"""

import io
import sys
from collections.abc import Callable
from dataclasses import dataclass

import pytest


@dataclass
class Result:
    """Outcome of a single `CliRunner.invoke` call."""

    exit_code: int  # 0 = success, 1 = CliError, 2 = argparse usage error
    stdout: str  # captured stdout, decoded as UTF-8 (replace on decode errors)
    stdout_bytes: bytes  # captured stdout as raw bytes (for binary-mode assertions)
    stderr: str  # captured stderr as text

    @property
    def output(self) -> str:
        """Click-compatibility alias for `stdout`."""
        return self.stdout


class _FakeStdin:
    """In-memory stdin supporting both text `.read()` and binary `.buffer.read()`."""

    def __init__(self, data: bytes) -> None:
        """Wrap `data` so it's readable as both text and bytes."""
        self._text = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="strict")
        self.buffer = self._text.buffer  # Raw bytes view for `read_bytes_input`

    def read(self, n: int = -1) -> str:
        """Read up to `n` characters of decoded text (all if negative)."""
        return self._text.read(n if n >= 0 else -1)

    def readable(self) -> bool:
        """Return True — this stdin is always readable."""
        return True


class _CapturingStdout:
    """Stdout replacement that captures both text writes and raw `.buffer` writes."""

    def __init__(self) -> None:
        """Initialize an empty in-memory capture buffer."""
        self._buf = io.BytesIO()  # Backing store for every write, text or binary
        self.buffer = self._buf  # Raw bytes view for `write_bytes_output`

    def write(self, s: str) -> int:
        """Encode `s` as UTF-8 and append to the capture buffer."""
        self._buf.write(s.encode("utf-8"))
        return len(s)

    def flush(self) -> None:
        """No-op — everything is buffered in memory already."""

    def get_bytes(self) -> bytes:
        """Return everything written so far as raw bytes."""
        return self._buf.getvalue()


class CliRunner:
    """In-process CLI harness — mimics `typer.testing.CliRunner` for this project."""

    def invoke(
        self,
        app: Callable[[list[str]], int],
        args: list[str],
        input: str | bytes | None = None,
    ) -> Result:
        """Run `app(args)` with `input` on stdin; capture stdout/stderr and exit code."""
        if input is None:
            stdin_bytes = b""
        elif isinstance(input, bytes):
            stdin_bytes = input
        else:
            stdin_bytes = input.encode("utf-8")

        real_stdin, real_stdout, real_stderr = sys.stdin, sys.stdout, sys.stderr
        fake_stdin = _FakeStdin(stdin_bytes)
        fake_stdout = _CapturingStdout()
        fake_stderr = io.StringIO()
        sys.stdin = fake_stdin
        sys.stdout = fake_stdout
        sys.stderr = fake_stderr
        try:
            try:
                code = app(args)
            except SystemExit as exc:
                # argparse calls sys.exit(2) on usage errors and sys.exit(0) for --help/--version.
                raw = exc.code
                if raw is None:
                    code = 0
                elif isinstance(raw, int):
                    code = raw
                else:
                    # Non-int exit codes (strings) coerce to 1 — same semantics as the stdlib.
                    code = 1
        finally:
            sys.stdin = real_stdin
            sys.stdout = real_stdout
            sys.stderr = real_stderr

        out_bytes = fake_stdout.get_bytes()
        out_text = out_bytes.decode("utf-8", errors="replace")
        return Result(exit_code=code, stdout=out_text, stdout_bytes=out_bytes, stderr=fake_stderr.getvalue())


@pytest.fixture
def runner() -> CliRunner:
    """In-process CLI runner — used by every command-level test."""
    return CliRunner()


@pytest.fixture
def err_text() -> Callable[[Result], str]:
    """Return a callable that combines stderr + stdout for error-path assertions."""

    def _extract(result: Result) -> str:
        return result.stderr + result.stdout

    return _extract
