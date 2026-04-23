# AI Agent Start Guide

## Critical: Language
RESPOND IN ENGLISH. Always. No exceptions.
User's language does NOT determine your response language.
Only switch if user EXPLICITLY requests it (e.g., "respond in {language}").
Language switching applies ONLY to chat. All code, comments, commit messages, and files must ALWAYS be in English — no exceptions.

## Mandatory Rules (external)
These files are REQUIRED. Read them fully and follow all rules.
- `~/.claude/shared-rules/general.md`
- `~/.claude/shared-rules/python.md`

## Project Reading (context)
These files are REQUIRED for project understanding.
- `README.md`
- `mm-crypt-cli/README.md`

## Preflight (mandatory)
Before your first response:
1. Read all files listed above.
2. Do not answer until all are read.
3. In your first reply, list every file you have read from this document.

Failure to follow this protocol is considered an error.

## CLI architecture rules

These apply to `mm-crypt-cli`. The `mm-crypt` library is a flat collection of modules with no layering.

1. No third-party CLI framework. Stdlib `argparse` only.
2. Per-command files in `commands/<group>/<verb>.py` for grouped commands, or `commands/<verb>.py` for top-level commands. One file per command.
3. Each command exposes `register(subparsers)` + `_run(args)` — `main.py` stays thin.
4. Raise `CliError(message, code)`; never `sys.exit()` directly from a command. Error codes are UPPER_SNAKE_CASE (`MISSING_SECRET`, `DECRYPTION_FAILED`, `INVALID_INPUT`, …).
5. `__init__.py` files stay empty (module docstring only) — no re-exports, no logic.
6. `pydantic` is not a dependency of `mm-crypt-cli`. Data classes use stdlib `@dataclass(frozen=True, slots=True)`.
