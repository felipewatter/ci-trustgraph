.PHONY: test compile coverage scan wheel

test:
	python -m unittest discover -s tests -v

compile:
	python -m compileall -q src tests

coverage:
	python -m coverage run --branch --source=ci_trustgraph -m unittest discover -s tests
	python -m coverage report -m

scan:
	ci-trustgraph . --fail-on high --format json --output ci-trustgraph-report.json

wheel:
	python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
