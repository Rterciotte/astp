.PHONY: test format lint

test:
	pytest

format:
	ruff check . --fix
	black .

lint:
	ruff check .
	black --check .
