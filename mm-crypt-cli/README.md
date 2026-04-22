# mm-crypt-cli

Command-line interface and TUI editor built on top of [mm-crypt](../mm-crypt/README.md).

> **Status:** Early development — Fernet group implemented; OpenSSL and scrypt commands (and the TUI editor) are planned next.

## Install

```bash
uv tool install mm-crypt-cli
```

This installs the `mm-crypt` executable.

## Commands

### Fernet

- `mm-crypt fernet keygen` — print a freshly generated Fernet key (URL-safe base64, 32 bytes of entropy).
- `mm-crypt fernet encrypt` — encrypt text; key from `--key` / `--key-file` / `--key-env` (exactly one); input from `--input` (or stdin); output to `--output` (or stdout).
- `mm-crypt fernet decrypt` — inverse of `encrypt`.

The group has alias `f`, and commands have single-letter aliases: `g` (keygen), `e` (encrypt), `d` (decrypt). So `mm-crypt f e -k …` is shorthand for `mm-crypt fernet encrypt --key …`.

All three key sources are mutually exclusive. `--key` is insecure — the value is recorded in shell history (and visible to other users via `ps`) — so prefer `--key-file` or `--key-env` for non-throwaway keys.

Example round-trip:

```bash
mm-crypt fernet keygen > my.key
echo -n "hello" | mm-crypt fernet encrypt --key-file my.key > token.txt
mm-crypt fernet decrypt --key-file my.key --input token.txt
```
