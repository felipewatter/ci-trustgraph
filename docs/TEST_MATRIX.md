# Test matrix and release criteria

## Local checks

```
python -m unittest discover -s tests -v
python -m compileall -q src tests
ci-trustgraph . --format json --fail-on high
ci-trustgraph . --format sarif --output trustgraph.sarif --fail-on high
```

## GitHub-hosted CI matrix

Python 3.11, 3.12, 3.13 on Ubuntu, Windows and macOS (nine matrix combinations). The same regression test suite is executed in each environment. CI builds a wheel on Ubuntu and validates an installed CLI invocation.

## Release acceptance

Do not publish release `v1.0.0` unless the *current head* CI workflow completes successfully. Check the tag target, release assets and checksums separately. When published, a tag must not be silently moved to a new commit; a new version is required.

## Known gaps

Line number in SARIF is currently a file-level location rather than a precise matched YAML source line. Unit tests demonstrate internal logic but do not certify detection of all exploitable cases. YAML aliases are rejected rather than expanded, to enforce deterministic resource use.
