# TUI Editor

`mm-crypt editor <path>` opens a scrypt-encrypted text file in a
terminal editor, lets you edit it in memory, and writes the edits back as a
fresh scrypt blob on Ctrl+S. The on-disk format is a plain `scrypt(1)`
container — fully interoperable with `mm-crypt scrypt encrypt` / `decrypt`
and the upstream `scrypt` CLI.

This document specifies **how the editor behaves** and **what security
properties it provides**, so a future reader can audit both quickly.

---

## Commands

| Command | Behavior |
| --- | --- |
| `mm-crypt editor <path>` | Open existing file, or create on first save if missing. Prompts for password once (existing) or twice with confirmation (new). |
| `mm-crypt editor <path> --view` / `-V` | Open read-only. Requires the file to exist. Save is disabled; buffer cannot be modified. |

Passwords are read via `getpass` — never accepted on the command line, in an
environment variable, or from a file. Interactive-only, by design: argv and
env leak to shell history, `ps`, and process introspection tools.

**Windows is not supported.** The editor uses POSIX `termios`, `fcntl`, and
`SIGWINCH`; on Windows the `editor` command exits immediately with a clear
error instead of trying to run.

---

## Flow

### Open

1. Apply runtime hardening (disable core dumps) — done up front, before any
   sensitive data is in process memory.
2. Resolve symlinks in `<path>` so the editor operates on the actual
   file. Editing a symlink writes through to the target, matching the
   default behavior of vim and emacs. The symlink itself is never
   replaced by a regular file.
3. **If the file exists:**
   1. Reject it if it is not a regular file.
   2. Read its bytes.
   3. Prompt for the password.
   4. `scrypt.decrypt_bytes` authenticates and decrypts — either returns the
      plaintext or raises. Wrong password, tampered file, and corrupted file
      all collapse into a single error ("wrong password or corrupted data");
      attackers gain no information from the distinction.
   5. Decode UTF-8 (error out if not text).
   6. Launch the TUI with the decrypted plaintext as the initial buffer.
4. **If the file does not exist:**
   1. `--view` → error: `File does not exist`.
   2. If `<path>.parent` does not exist → error:
      `Parent directory does not exist: <parent>`. No password prompt. The
      user must `mkdir -p` the parent themselves; we don't silently create
      arbitrary directory hierarchies.
   3. Prompt for the password twice (password + confirmation); reject on
      mismatch.
   4. Launch the TUI with an empty buffer.

### Edit

The buffer is a `TextBuffer` (our own data structure) rendered by
`TextAreaView` (our own renderer). All state — cursor position, the text
itself — lives in memory. Nothing is written to disk during editing.

Key bindings:

| Key | Action |
| --- | --- |
| `Ctrl+S` | Save (re-encrypt the buffer and replace the file atomically) |
| `Ctrl+Q` / `Ctrl+C` | Quit (prompts inline in the status bar if the buffer has unsaved changes) |
| Arrow keys, `Home`, `End`, `PageUp`, `PageDown` | Cursor movement |
| `Enter`, `Tab`, printable characters | Insert (unless `--view`) |
| `Backspace`, `Delete` | Delete (unless `--view`) |

Bracketed paste is enabled on startup (`CSI ?2004h`); a multi-line paste
from the system clipboard arrives as one insert operation rather than
triggering per-line Enter handling.

There is no undo. This is a deliberate simplification — see "Project
structure" below for the reasoning.

### Save

```
buffer (RAM)
  → scrypt.encrypt_bytes → ciphertext (RAM)
  → tempfile.mkstemp(dir=path.parent, prefix=".<name>.", suffix=".tmp")
      – mode 0600 (owner only), same filesystem as target
  → write ciphertext + flush + fsync
  → Path.replace(path)          ← atomic POSIX rename
```

A crash at any point produces one of these outcomes:

| Crash point | `<path>` state | Tmp sibling state |
| --- | --- | --- |
| Before `mkstemp` | Old, intact | — |
| During write to tmp | Old, intact | Partial ciphertext (garbage, but ciphertext) |
| Between write and `replace` | Old, intact | Complete new ciphertext |
| During `replace` | Atomic — old OR new, never both | Renamed away |
| After `replace` | New ciphertext | — |

**`<path>` is never in a partially-written state.** That is the guarantee.

### Quit

- Read-only or unmodified buffer → exit immediately.
- Modified buffer → inline prompt in the status row:
  `Unsaved changes. Save?  [y]es   [n]o (discard)   [c]ancel`.
  - `y` / `Y`: run the save flow above, then exit. If save fails, stay in
    the editor (the buffer is still modified).
  - `n` / `N`: exit without saving. The plaintext buffer is dropped when the
    process exits.
  - `c` / `C` / `Ctrl+C` / `Ctrl+Q`: dismiss the prompt, stay in the editor.

The prompt is a single row of text at the bottom of the screen — no modal
dialog, no centered window, no button widgets. The editor is a minimal
screen + one status line.

---

## Security model

### What the editor guarantees

1. **On-disk invariant: ciphertext only, ever.** The only bytes this editor
   writes to disk — to `<path>` itself or to the tmp sibling — are the
   output of `scrypt.encrypt_bytes`. Plaintext never reaches the disk via
   our code. The tmp file is not a "decryption cache"; it is a staging area
   for the *next* ciphertext.

2. **Atomic replacement.** `<path>` is never observable in a
   partially-written state. Either it is the old complete ciphertext or the
   new complete ciphertext. A half-written scrypt file would fail HMAC
   verification and be permanently unrecoverable; this is the sole reason
   the tmp+rename pattern exists.

3. **Tmp-file permissions.** `tempfile.mkstemp` creates the tmp with mode
   `0600` — owner read/write only. World and group have no access.

4. **Authenticated format.** The scrypt(1) container authenticates the
   header and the full ciphertext with HMAC-SHA-256. Tampering is detected;
   wrong passwords and tampered files are indistinguishable to the caller
   (by design).

5. **Password handling.** The password is read with `getpass` — hidden
   echo, from the controlling TTY. It is never accepted via flag, env var,
   or file, so it cannot be captured from shell history, `ps`, or the
   environment. It is kept in process memory only for the lifetime of the
   editor.

6. **No environment-variable configuration.** The editor's rendering and
   key handling consult **zero** environment variables. There is no
   `$TERM` lookup, no terminfo DB access, no debug-log env, no screenshot
   env. What the user sets in their shell cannot redirect plaintext out of
   the process through any code we control.

7. **Terminal-escape injection from file contents.** When rendering, every
   C0 control character (0x00–0x1F) and DEL (0x7F) in the buffer is
   replaced with caret notation (`^[`, `^A`, `^?`, etc.). A buffer that
   happens to contain raw ANSI escape bytes cannot cause the terminal to
   execute them.

### What the editor does NOT guarantee

The following are **residual risks** that a single Python application
cannot eliminate. They apply equally to vim, emacs, VS Code — any editor
with a plaintext buffer.

1. **OS swap / hibernation.** The kernel may page process memory to disk,
   and that memory includes the plaintext buffer. Full mitigation requires
   `mlock`, which has tight system limits and a heavy implementation cost.
   Not implemented.

2. **Terminal scrollback.** Whatever the editor paints on screen is
   visible to the terminal emulator and may be retained in its scrollback
   buffer or in a session-dump tool like `tmux`. User's responsibility.

3. **Core dumps.** A crashing process can produce a core file containing
   raw memory — including the plaintext buffer. We lower `RLIMIT_CORE` to
   zero at startup (best-effort via `resource.setrlimit`) so the kernel
   will not write a core for our process. A system-wide dump collector
   (like `systemd-coredump` or macOS `ReportCrash`) may still capture cores
   if it has higher privileges than we do.

4. **Python-level diagnostic env vars.** `PYTHONFAULTHANDLER`,
   `PYTHONTRACEMALLOC`, and similar can produce diagnostic output on
   crash. These do not normally contain user buffer content (they dump
   stack traces and allocation sites, not local string values), but they
   are a residual surface that a Python-based editor cannot eliminate
   without sandboxing the interpreter itself.

5. **Hostile local attacker.** Any attacker with arbitrary code execution
   in the user's session (shell, `LD_PRELOAD`, ptrace attach, replaced
   binary, keylogger) can bypass every in-process defense. The editor is
   not hardened against this threat model — nor is any other editor.

### Why no TUI library

The editor is written directly on POSIX `termios` and hardcoded ANSI escape
sequences. We do **not** use Textual, urwid, prompt_toolkit, curses, or any
other TUI library.

The reason is specific and narrow. TUI libraries accumulate disk-write side
channels driven by environment variables:

- Textual reads `TEXTUAL_LOG`, `TEXTUAL_DEBUG`, `TEXTUAL_SCREENSHOT`,
  `TEXTUAL_SCREENSHOT_LOCATION`, `TEXTUAL_SCREENSHOT_FILENAME` — any of
  which can redirect rendered buffer contents (including `TextArea` text)
  to a file on disk without modifying our code.
- ncurses reads `NCURSES_TRACE`, which opens a `trace` file in CWD and
  writes every input/output byte to it.
- urwid has had configurable debug log paths over its history.

A defense that scrubs these variables before launch is a **blocklist**. A
blocklist is not durable: the next upstream release of the library may add
a new variable we do not know about, and a user whose shell environment
sets it will have buffer content routed to disk without any warning. Our
own code audit does not help — the write happens inside the library.

Writing the TUI ourselves moves the property from "blocklist of
known-dangerous env vars, hopefully complete" to "the class is empty".
Our code consults no environment variables for rendering or key handling.
There is no terminfo lookup; the sequences we emit (alt-screen,
bracketed-paste, cursor move, clear-line, reverse-video) are hardcoded
xterm/VT100 constants that every modern terminal emulator implements
(iTerm2, Terminal.app, Alacritty, kitty, Ghostty, gnome-terminal, konsole,
tmux, screen).

The cost is modest — a hand-rolled terminal layer is a few hundred lines
split across five files (see "Project structure"). None of the failure
modes of a self-rolled TUI are in the same risk class as "buffer content
silently written to disk": rendering bugs produce visible glitches, not
leaks; in-memory buffer bugs produce data-integrity issues, not leaks.
The Python interpreter is memory-safe, so there is no buffer-overflow
surface to worry about.

As of the argparse migration, `mm-crypt-cli` no longer depends on
`mm-clikit` (or typer, click, textual, rich, markdown-it, pydantic). The
only runtime dependency is `mm-crypt`, which in turn depends only on
`cryptography`. Textual is not in `uv.lock`; the security property now
holds at both runtime and package-list level.

---

## Project structure

`mm-crypt-cli/src/mm_crypt_cli/simpletui/` is split by role:

| Module | Role |
| --- | --- |
| `terminal.py` | Raw-mode I/O: `termios` setup, alt-screen, bracketed paste, SIGWINCH self-pipe, cursor/clear ANSI helpers. |
| `keys.py` | Incremental byte-stream → `KeyEvent` parser. Handles CSI/SS3 sequences and bracketed paste framing. |
| `buffer.py` | `TextBuffer`: multi-line text + cursor. Pure data structure, no rendering. |
| `view.py` | `TextAreaView`: draws a `TextBuffer` into a viewport with horizontal scroll, wide-char width handling, and caret notation for controls. |
| `editor.py` | `EditorApp`: wires the above, owns path/password, runs the event loop, implements Ctrl+S and the inline quit prompt. |
| `coredump.py` | `disable_core_dumps()`: best-effort `RLIMIT_CORE` = 0. |

The dependency direction is strict: `editor` → `view` → `buffer` + `keys` +
`terminal`. The lower modules have no knowledge of scrypt, file paths, or
passwords — they are reusable primitives. The app-specific concerns live
only in `editor.py`.

Deliberate omissions from the hand-rolled layer, vs. a full editor:

- **No undo history.** The editor works on small text notes; making undo
  correct under paste, newlines, and line joins is non-trivial code that
  would not earn its weight.
- **No soft-wrap.** Long lines scroll horizontally. Simpler logic, fewer
  moving parts around cursor positioning and wide characters.
- **No selection or clipboard integration.** Paste from the system
  clipboard is handled by bracketed paste; copy-out is deliberately not
  implemented (OSC 52 would be an additional disk/network-adjacent side
  channel).
- **No mouse.** Keyboard only.

Each omission was evaluated against both "do users need this?" and "does
this add a leak vector?". When in doubt, we left it out.

---

## Tmp-file FAQ

### Why is there a tmp file at all?

To make the save operation atomic. See the "Save" section above. Without
tmp+rename, a crash mid-write corrupts the scrypt file and makes it
permanently unrecoverable (HMAC fails). With tmp+rename, the original is
either fully replaced by the new version or not touched at all.

### Does the tmp file ever contain plaintext?

No. The encryption happens in memory; only the already-encrypted bytes are
written to the tmp. The invariant "plaintext never touches disk" holds for
both `<path>` and the tmp sibling.

### I see a file called `.mynotes.scrypt.XXXXXXXX.tmp` in my directory. What is it?

A leftover tmp from a previous save that was interrupted (process killed,
laptop powered off mid-save, etc.). Its contents are encrypted with the
same password as the main file, so it is not a plaintext leak. It is safe
to delete manually:

    rm .mynotes.scrypt.*.tmp

We do not automatically delete orphaned tmps on open, because in principle
one of them could be a complete newer ciphertext that the user might want
to inspect.

### Why not just write directly to the file and skip the tmp?

Because the scrypt(1) format is a single authenticated blob: `header ||
ciphertext || HMAC`. Any partial write — even one byte missing — fails
HMAC verification on the next decrypt. A direct in-place write that
crashes halfway produces a file that no one can ever read again, even
with the correct password. The tmp+rename pattern is exactly what `git`,
`SQLite`, and every serious editor use to avoid this.

### Why is the tmp file in the same directory as the target?

Atomic rename is only guaranteed when source and destination are on the
same filesystem. If the tmp were in `/tmp` and the target under `/home`,
and those are separate mounts (common on macOS and on Linux with
home-on-separate-partition setups), `os.replace` would fall back to
copy-then-unlink — which is not atomic, and also routes the ciphertext
through a world-readable location longer than necessary.

---

## Related files

- `mm-crypt-cli/src/mm_crypt_cli/commands/editor.py` — the `editor`
  top-level command: Windows gate, core-dump disable, path + password
  resolution, then hands off to the TUI.
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/terminal.py` — raw-mode terminal
  session (termios, alt-screen, SIGWINCH, ANSI helpers).
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/keys.py` — byte-stream → `KeyEvent`
  parser.
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/buffer.py` — `TextBuffer` data
  structure.
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/view.py` — `TextAreaView` renderer.
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/editor.py` — `EditorApp` and the
  `_write_encrypted` atomic-save helper.
- `mm-crypt-cli/src/mm_crypt_cli/simpletui/coredump.py` — `disable_core_dumps()`.
- `mm-crypt/src/mm_crypt/scrypt.py` — the scrypt(1)-compatible format
  implementation that both the CLI and the TUI use.
