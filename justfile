set dotenv-load

lib_version := `grep -m1 '^version *=' mm-crypt/pyproject.toml | cut -d'"' -f2`
cli_version := `grep -m1 '^version *=' mm-crypt-cli/pyproject.toml | cut -d'"' -f2`

clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage
    rm -rf dist
    rm -rf mm-crypt/build mm-crypt/src/*.egg-info
    rm -rf mm-crypt-cli/build mm-crypt-cli/src/*.egg-info

format:
    uv run ruff check --select I --fix mm-crypt mm-crypt-cli
    uv run ruff format mm-crypt mm-crypt-cli

lint: format
    uv run ruff check mm-crypt mm-crypt-cli
    uv run mypy mm-crypt/src mm-crypt-cli/src

test:
    uv run pytest -n auto mm-crypt/tests mm-crypt-cli/tests

audit:
    uv export --no-dev --format requirements-txt --no-emit-project --no-emit-workspace > requirements.txt
    uv run pip-audit -r requirements.txt --disable-pip
    rm requirements.txt
    uv run bandit --silent --recursive --configfile "pyproject.toml" mm-crypt/src mm-crypt-cli/src

build-lib: clean lint audit test
    cd mm-crypt && uv build

build-cli: clean lint audit test
    cd mm-crypt-cli && uv build

publish-lib: build-lib
    #!/usr/bin/env bash
    set -euo pipefail
    git diff-index --quiet HEAD
    printf "PyPI token: " >&2
    IFS= read -rs TOKEN
    echo >&2
    uv publish --token "$TOKEN" dist/mm_crypt-*.whl dist/mm_crypt-*.tar.gz
    git tag -a 'mm-crypt-v{{lib_version}}' -m 'mm-crypt-v{{lib_version}}'
    git push origin 'mm-crypt-v{{lib_version}}'

publish-cli: build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    git diff-index --quiet HEAD
    printf "PyPI token: " >&2
    IFS= read -rs TOKEN
    echo >&2
    uv publish --token "$TOKEN" dist/mm_crypt_cli-*.whl dist/mm_crypt_cli-*.tar.gz
    git tag -a 'mm-crypt-cli-v{{cli_version}}' -m 'mm-crypt-cli-v{{cli_version}}'
    git push origin 'mm-crypt-cli-v{{cli_version}}'

sync:
    uv sync
