# Validation report — CI TrustGraph v1.0.0

**Local validation date:** 2026-11-01. **Platform:** Linux, Python 3.13.5. This report summarizes tests actually executed in the development environment. It is **not** a third-party security audit.

| Check | Result | Details |
|---|---|---|
| Unit and regression tests | PASS | **79 unittest tests**, all successful; see `ci-trustgraph-tests.log`. |
| Deterministic property-style tests | PASS | **1,500 trials** inside the test suite (1,000 artifact path classifications + 500 token permission evaluations). |
| Code coverage | PASS | **95%** combined statement and branch coverage using `coverage.py`; excludes vendored dependencies. |
| Source compilation | PASS | `python -m compileall -q src tests`. |
| Wheel build | PASS | `pip wheel . --no-deps --no-build-isolation`; wheel metadata + checksum validated. |
| Wheel installation | PASS | Isolated Python venv, installed distribution and its PyYAML 6.0.3 dependency. Because outbound package index resolution was disabled, the preinstalled PyYAML package was copied into the isolated venv. |
| Installed CLI execution | PASS | Scan of the repository's own workflow files; exit 0 with `--fail-on high`. |
| Dependency consistency | PASS | `pip check` in the isolated venv returned `No broken requirements found.` |
| Synthetic high-risk pipeline | PASS | Links PR producer upload to privileged `workflow_run` consumer; emits one `TG009` critical finding with 5-hop trust path; exit code 2. |
| Synthetic safe pipeline | PASS | Generates zero findings; exit code 0. |
| JSON and SARIF generation | PASS | Tests assert report schema and rule IDs; SARIF version 2.1.0. |
| Bounded/unsafe input handling | PASS | Tests for symlinked workflows, excessive files, oversized input, YAML aliases, duplicate keys, malformed encoding and object tags. |
| GitHub Actions remote matrix | **NOT RUN** | Requires first publication to the new GitHub repository. |
| GitHub release | **NOT PUBLISHED** | Must follow a successful remote CI run; GitHub connector cannot create a new repository. |
| Vulnerability advisory / action authenticity checks | **NOT RUN** | Offline design intentionally does not query advisories or verify commit SHA ownership. |

## Results interpretation

The self-scan reported two **medium**-severity indicators on the release workflow (token write permission and privileged event). These are contextual flags about release automation with a write token, not evidence that a vulnerability is present. The release pipeline is scoped to successful `CI` runs of `push` on the `main` branch, checks the source repository identity, checks out the successful commit by SHA and does not download upstream workflow artifacts.

## Known limitations

The `TG009` transfer path is **heuristic**: it cannot prove the downloaded artifact is the script that executes later. Dynamic conditions, step transitive actions and organization permission configuration are outside the local YAML model. SARIF currently reports file-level location at startLine=1. These limitations are documented in README, THREAT_MODEL and RULES.

## Final release checklist

After creating `felipewatter/ci-trustgraph`, publish exactly the distribution source files. Confirm GitHub Actions nine-job matrix success, verify all uploads, compare release tag SHA with the tested commit SHA and confirm downloadable ZIP plus SHA-256 checksum. Until those checks are complete, publication is pending.
