.PHONY: venv test lint format upgrade-db run-api

venv:
	bash scripts/setup_python_dev.sh

test:
	. .venv/bin/activate && pytest

lint:
	. .venv/bin/activate && ruff check .

format:
	. .venv/bin/activate && black .

upgrade-db:
	. .venv/bin/activate && alembic upgrade head

run-api:
	. .venv/bin/activate && uvicorn api.app.main:app --host 0.0.0.0 --port 8000
