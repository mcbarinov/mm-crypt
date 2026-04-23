# TUI Editor

`mm-crypt scrypt edit <path>` opens a scrypt-encrypted text file in a
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
| `mm-crypt scrypt edit <path>` | Open existing file, or create on first save if missing. Prompts for password once (existing) or twice with confirmation (new). |
| `mm-crypt scrypt edit <path> --view` / `-V` | Open read-only. Requires the file to exist. Save is disabled; buffer cannot be modified. |

Passwords are read via `getpass` — never accepted on the command line, in an
environment variable, or from a file. Interactive-only, by design: argv and
env leak to shell history, `ps`, and process introspection tools.

---

## Flow

### Open

1. Apply runtime hardening (disable core dumps, scrub Textual debug env
   vars) — done up front, before any sensitive data is in process memory.
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

The buffer is a Textual `TextArea` widget. All state — cursor, undo history
(up to 50 checkpoints), the text itself — lives in memory. Nothing is
written to disk during editing.

Key bindings:

| Key | Action |
| --- | --- |
| `Ctrl+S` | Save (re-encrypt the buffer and replace the file atomically) |
| `Ctrl+Q` | Quit (prompts if the buffer has unsaved changes) |
| `Esc` | Cancel the quit-confirmation modal |

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
- Modified buffer → modal dialog: Save / Discard / Cancel.
  - Save: run the save flow above, then exit. If save fails, stay in the
    editor (the buffer is still modified).
  - Discard: exit without saving. The plaintext buffer is dropped when the
    process exits.
  - Cancel / Esc: dismiss the modal, stay in the editor.

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
   (like `systemd-coredump`) may still capture cores if it has higher
   privileges than we do.

4. **Hostile local attacker.** Any attacker with arbitrary code execution
   in the user's session (shell, `LD_PRELOAD`, ptrace attach, replaced
   binary, keylogger) can bypass every in-process defense. The editor is
   not hardened against this threat model — nor is any other editor.

### Textual: dependency-specific caveat

The TUI uses [Textual](https://textual.textualize.io/). Textual reads a few
environment variables that, when set, cause Textual itself to write to
disk:

- **`TEXTUAL_LOG=<path>`** — appends all log output (including any
  `app.log(...)` calls) to `<path>`.
- **`TEXTUAL_DEBUG=1`** — opens `keys.log` in the current working
  directory and records every key sequence.
- **`TEXTUAL_SCREENSHOT=<seconds>`** — on exit, writes an SVG snapshot of
  the rendered screen — which contains `TextArea` content — to disk.
- **`TEXTUAL_SCREENSHOT_LOCATION` / `TEXTUAL_SCREENSHOT_FILENAME`** —
  where the above SVG lands.

An attacker who can set environment variables for our process (via
`.envrc`, a modified shell init, `env FOO=bar mm-crypt …`, etc.) could
redirect plaintext to disk without modifying our code. **As a defense in
depth, we delete all five variables from `os.environ` before launching the
Textual app.** Our scrub takes effect in our own process only — it does
not alter the user's shell. If these variables are set persistently in a
shell init file, we still scrub them at start; but we cannot prevent a
user from setting them and then running our binary from that same shell:
Textual sees our scrubbed environment, but anyone also running Textual
from that shell for other purposes will not be protected.

### Future work: replace Textual

Textual is a large dependency with a broad feature surface (logging,
screenshots, devtools, serve-to-web). Every new Textual version may add a
new way for buffer content to reach disk or the network. Long term, the
plan is to **replace Textual with a minimal hand-rolled TUI** that does
nothing except paint a buffer and handle key input — no logging, no
screenshots, no devtools, no external servers. That reduces this entire
attack surface to a few hundred lines of our own code.

This is deliberately out of scope for the current implementation; the
Textual-based editor ships first, and the replacement will be a separate
effort once the broader editor design is stable.

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

- `mm-crypt-cli/src/mm_crypt_cli/cli/commands/scrypt/edit.py` — the `edit`
  subcommand: path + password resolution, then hands off to the TUI.
- `mm-crypt-cli/src/mm_crypt_cli/tui/app.py` — `EditorApp`, `QuitConfirm`,
  and `_write_encrypted` (the atomic save helper).
- `mm-crypt-cli/src/mm_crypt_cli/tui/hardening.py` — env-var scrub +
  core-dump disable; called once, immediately before `App.run()`.
- `mm-crypt/src/mm_crypt/scrypt.py` — the scrypt(1)-compatible format
  implementation that both the CLI and the TUI use.
