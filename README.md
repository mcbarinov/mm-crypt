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

## Development

This repo is a [uv workspace](https://docs.astral.sh/uv/concepts/projects/workspaces/). Both packages share a single virtual environment, lockfile, and dev tool configuration.

```bash
uv sync                  # install both packages in editable mode
just lint                # ruff + mypy across both packages
just test                # pytest across both packages
```

## Architecture

CLI architecture (layers, context, commands) is described in [docs/cli-architecture.md](./docs/cli-architecture.md). It applies only to `mm-crypt-cli`; the `mm-crypt` library is a flat collection of modules with no Core/Service layering.
