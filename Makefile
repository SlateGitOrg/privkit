# privkit developer tasks. `make check` is the single gate (also run by CI).
UV ?= uv
COV_MIN ?= 90
SPACY_MODEL_URL = https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

.PHONY: help sync check format-check format lint type test cov demo eval bench fixtures ner-model loc clean

help:
	@echo "check       format-check + lint + type-check + tests with coverage >= $(COV_MIN)%"
	@echo "demo        offline end-to-end demo on bundled fixtures"
	@echo "eval        detector precision/recall on the synthetic dev/test corpus"
	@echo "bench       micro-benchmarks (writes eval/bench.json)"
	@echo "ner-model   install the optional spaCy extra + en_core_web_sm (network)"

sync:
	$(UV) sync --frozen

check: sync format-check lint type cov

format-check:
	$(UV) run --frozen ruff format --check .

format:
	$(UV) run --frozen ruff format .
	$(UV) run --frozen ruff check --fix .

lint:
	$(UV) run --frozen ruff check .

type:
	$(UV) run --frozen mypy

test:
	$(UV) run --frozen pytest

cov:
	$(UV) run --frozen pytest --cov --cov-report=term --cov-fail-under=$(COV_MIN)

demo: sync
	bash scripts/demo.sh

eval:
	$(UV) run --frozen python -u scripts/eval_detector.py

bench:
	$(UV) run --frozen python -u scripts/bench.py

fixtures:
	$(UV) run --frozen python -u scripts/make_fixtures.py

ner-model:
	$(UV) sync --frozen --extra ner
	$(UV) pip install "en_core_web_sm @ $(SPACY_MODEL_URL)"

loc:
	@echo "non-test source lines (src/privkit, excluding blanks and comments):"
	@find src/privkit -name '*.py' -print0 | xargs -0 cat | grep -vE '^\s*(#|$$)' | wc -l
	@echo "test lines:"
	@find tests -name '*.py' -print0 | xargs -0 cat | grep -vE '^\s*(#|$$)' | wc -l

clean:
	rm -rf out .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
