set dotenv-load

clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage
    rm -rf mm-crypt/dist mm-crypt/build mm-crypt/src/*.egg-info
    rm -rf mm-crypt-cli/dist mm-crypt-cli/build mm-crypt-cli/src/*.egg-info

format:
    uv run ruff check --select I --fix mm-crypt mm-crypt-cli
    uv run ruff format mm-crypt mm-crypt-cli

lint: format
    uv run ruff check mm-crypt mm-crypt-cli
    uv run mypy mm-crypt/src mm-crypt-cli/src

test:
    uv run pytest -n auto mm-crypt/tests mm-crypt-cli/tests

audit:
    uv export --no-dev --format requirements-txt --no-emit-project > requirements.txt
    uv run pip-audit -r requirements.txt --disable-pip
    rm requirements.txt
    uv run bandit --silent --recursive --configfile "pyproject.toml" mm-crypt/src mm-crypt-cli/src

build-lib: clean lint audit test
    cd mm-crypt && uv build

build-cli: clean lint audit test
    cd mm-crypt-cli && uv build

sync:
    uv sync
