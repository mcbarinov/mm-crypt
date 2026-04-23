# mm-crypt-cli

Command-line interface and TUI editor built on top of [mm-crypt](../mm-crypt/README.md). Stdlib `argparse` only — the one runtime dependency is `mm-crypt` itself, which depends only on `cryptography`.

## Install

```bash
uv tool install mm-crypt-cli
```

This installs the `mm-crypt` executable.

## Commands

```
mm-crypt fernet  (f)  keygen   (g)
                      encrypt  (e)
                      decrypt  (d)
mm-crypt openssl (o)  encrypt  (e)
                      decrypt  (d)
mm-crypt scrypt  (s)  encrypt  (e)
                      decrypt  (d)
mm-crypt editor  (e)  <path>
```

Groups and commands have single-letter aliases, so `mm-crypt f e -k …` is shorthand for `mm-crypt fernet encrypt --key …`.

### Secret sources

Every command that needs a key or password takes exactly one of three mutually exclusive flags:

| Flavor | Flags |
| --- | --- |
| Fernet key | `--key` / `--key-file` / `--key-env` |
| Password | `--password` / `--password-file` / `--password-env` |

`--key` / `--password` are insecure — the literal value is recorded in shell history and visible via `ps`. Prefer `--key-file` / `--password-file` or `--key-env` / `--password-env` for anything non-throwaway.

### I/O convention

All encrypt/decrypt commands read from `--input` / `-i` (default: stdin) and write to `--output` / `-o` (default: stdout).

### Text vs. binary

OpenSSL and scrypt commands accept `--binary` / `-b`:

- default (no flag): UTF-8 text in, base64 out on encrypt; base64 in, UTF-8 text out on decrypt;
- `--binary`: raw bytes on both sides.

Fernet is text-only (its tokens are already URL-safe base64).

## Fernet

```bash
mm-crypt fernet keygen > my.key
echo -n "hello" | mm-crypt fernet encrypt --key-file my.key > token.txt
mm-crypt fernet decrypt --key-file my.key --input token.txt
```

## OpenSSL (AES-256-CBC)

Fully interoperable with the `openssl enc` CLI binary. Equivalent `openssl(1)` invocations:

```
encrypt (base64):   openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -base64 -pass pass:PASS -in in.txt -out out.b64
decrypt (base64):   openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -base64 -pass pass:PASS -in in.b64 -out out.txt
encrypt (--binary): openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -pass pass:PASS -in in.bin -out out.bin
decrypt (--binary): openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass pass:PASS -in in.bin -out out.bin
```

```bash
echo -n "hello" | mm-crypt openssl encrypt --password-env MYPASS > out.b64
mm-crypt openssl decrypt --password-env MYPASS --input out.b64
```

## scrypt (Tarsnap `scrypt(1)`-compatible)

Fully interoperable with the upstream `scrypt` binary (`brew install scrypt` / `apt install scrypt` / `pacman -S scrypt`). Base64 mode wraps the same binary blob for text pipelines; `scrypt(1)` has no native base64 mode.

KDF parameters (`--log-n` / `-N`, `--r`, `--p`) are only meaningful on `encrypt`; on `decrypt` they're read from the file header — no flags needed.

```bash
echo -n "hello" | mm-crypt scrypt encrypt --password-env MYPASS > out.b64
mm-crypt scrypt decrypt --password-env MYPASS --input out.b64
```

## editor

`mm-crypt editor <path>` opens a scrypt-encrypted text file in a hand-rolled terminal editor, decrypts it in memory, and writes the edits back as a fresh scrypt blob on Ctrl+S. Creates the file on first save if it doesn't exist.

```bash
mm-crypt editor notes.scrypt            # edit (or create)
mm-crypt editor notes.scrypt --view     # read-only
```

The password is read interactively via `getpass` and is never accepted via flag, env var, or file. POSIX only (uses `termios`, `fcntl`, `SIGWINCH`); Windows is not supported.

Full design and security spec — flow, atomic-save guarantees, threat model, why we don't use a TUI library — in [docs/tui-editor.md](./docs/tui-editor.md).

## Exit codes and error format

| Exit | Meaning |
| --- | --- |
| `0` | Success (or `--help` / `--version`). |
| `1` | Recoverable error. Printed to stderr as `Error: <message> [<CODE>]`, where `<CODE>` is an UPPER_SNAKE_CASE token (`MISSING_SECRET`, `DECRYPTION_FAILED`, `INVALID_INPUT`, …). |
| `2` | argparse usage error (unknown option, missing subcommand). |
