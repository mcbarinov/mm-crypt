# mm-crypt

Monorepo containing two packages that evolve together but publish independently:

- [`mm-crypt`](./mm-crypt) — cryptography library (OpenSSL AES-256-CBC, Fernet, scrypt). Minimal dependencies (`cryptography` only).
- [`mm-crypt-cli`](./mm-crypt-cli) — CLI and TUI editor built on top of `mm-crypt`.

## Install

Library only:

```bash
uv add mm-crypt
```

CLI and TUI editor:

```bash
uv tool install mm-crypt-cli
```

The CLI package depends on the library; the library does **not** depend on any CLI tooling, so library consumers get a clean dependency graph with only `cryptography`.


## Documentation

- [`mm-crypt-cli/README.md`](./mm-crypt-cli/README.md) — full CLI reference: command tree, secret-source flags, round-trip examples per group.
- [`mm-crypt-cli/docs/tui-editor.md`](./mm-crypt-cli/docs/tui-editor.md) — TUI editor design and security model (flow, atomic save, threat model).
