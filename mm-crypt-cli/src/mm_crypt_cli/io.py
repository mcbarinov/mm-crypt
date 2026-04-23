"""Input / output helpers for stdin / stdout and file-backed data."""

import sys
from pathlib import Path


def read_text_input(input_path: Path | None) -> str:
    """Read UTF-8 text from ``input_path`` or stdin."""
    if input_path is None:
        return sys.stdin.read()
    return input_path.read_text(encoding="utf-8")


def read_bytes_input(input_path: Path | None) -> bytes:
    """Read raw bytes from ``input_path`` or stdin."""
    if input_path is None:
        return sys.stdin.buffer.read()
    return input_path.read_bytes()


def write_text_output(data: str, output_path: Path | None) -> None:
    """Write UTF-8 text to ``output_path`` or stdout."""
    if output_path is None:
        sys.stdout.write(data)
        sys.stdout.flush()
    else:
        output_path.write_text(data, encoding="utf-8")


def write_bytes_output(data: bytes, output_path: Path | None) -> None:
    """Write raw bytes to ``output_path`` or stdout."""
    if output_path is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        output_path.write_bytes(data)
