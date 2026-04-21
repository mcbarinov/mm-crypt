# mm-crypt

Cryptography library with three independent modules:

- **OpenSSL AES-256-CBC** — full compatibility with the OpenSSL command-line tool.
- **Fernet** — simple authenticated symmetric encryption.
- **scrypt** — password-based encryption with the scrypt KDF.

> **Status:** Early scaffolding — no real functionality yet.

## Install

```bash
uv add mm-crypt
```

For the command-line interface and TUI editor, install the companion package:

```bash
uv add mm-crypt-cli
```

`mm-crypt` itself depends only on `cryptography` — no CLI tooling is pulled in.
