env_path = .env

install:
	uv venv --python 3.14 --allow-existing
	uv pip install -e .[dev]
	uv run pre-commit install

run:
	uv run dotenv -f "$(env_path)" run uvicorn api.main:app --reload

lint:
	uv run pre-commit run --all-files
