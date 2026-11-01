<div align="center">

# CI TrustGraph

**Offline cross-workflow trust-boundary analysis for GitHub Actions**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE) [![Security](https://img.shields.io/badge/security-offline%20analysis-blue)](SECURITY.md)

*Understand how untrusted events, privileged jobs, artifacts and executable steps interact — before a workflow is deployed.*

</div>

## Why it exists

Security reviews commonly inspect a workflow file in isolation. A real CI pipeline may instead cross multiple trust boundaries: a contributor-triggered workflow builds and uploads an artifact; a separate `workflow_run` workflow retrieves the artifact and executes a command with broader permissions. The risk is not visible in either YAML file alone.

**CI TrustGraph** analyzes the repository's `.github/workflows` directory and produces a deterministic, explainable **trust graph** plus risk findings. Each cross-workflow finding includes an evidence path from a producer through the consumer. This is a *heuristic code-analysis tool*, not an exploitation framework, a proof of arbitrary code execution or a replacement for Zizmor, Actionlint or CodeQL.

## Feature summary

| Capability | Description |
|---|---|
| Event-aware analysis | Maps `push`, `pull_request`, `pull_request_target`, `issue_comment`, and `workflow_run` trigger trust classes. |
| Token privilege audit | Flags implicit permissions and explicit write scopes, including job overrides. |
| Shell expression detection | Identifies direct interpolation of selected untrusted GitHub expressions into `run` scripts. |
| PR checkout boundary | Flags checkout of PR head revisions in privileged event workflows. |
| Cross-workflow artifact paths | Links producer uploads to workflow_run consumers with download + later execution-like command. |
| Runner and action checks | Identifies self-hosted runners for lower-trust events, unpinned remote actions and persisted checkout credentials. |
| CI-friendly output | Human-readable text, JSON with stable finding fingerprints, SARIF 2.1.0 and a machine-readable trust graph. |
| Regression guard | Compares findings to a previous JSON scan; only newly introduced findings fail `--fail-on` when `--baseline` is used. |
| Safe offline loading | YAML safe loader, duplicate key rejection, alias rejection, bounded input and symlink protection. |

## Installation

Python **3.11 or later**. Use a virtual environment. Package requires `PyYAML>=6.0.2,<7` and does **not** contact GitHub or any external service during analysis.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\\Scripts\\Activate.ps1
python -m pip install -e .
ci-trustgraph --help
```

For reproducible deployments, pin resolved dependency versions and hashes in your own environment. `pip install -e .` is for development convenience.

## Quick start

```bash
# Analyze repository in the current directory (default fail-on: high)
ci-trustgraph . --format text

# Save evidence and trust graph
ci-trustgraph . --format json --output report.json --graph trust-edges.json --fail-on off

# SARIF 2.1.0 for code scanning platforms
ci-trustgraph . --format sarif --output trustgraph.sarif --fail-on high

# Compare against a captured baseline, fail only on newly introduced issues
ci-trustgraph . --baseline previous-report.json --format json --output current-report.json

# Alternative without installing console script
PYTHONPATH=src python -m ci_trustgraph . --format text
```

**Exit codes:** `0` = no findings meeting the fail threshold; `2` = security findings meet or exceed the threshold; `3` = malformed input, inaccessible file, or report error. Use `--fail-on off` to produce reports without failing a pipeline.

## Demonstration: cross-workflow trust path

Consider two files, `PR Validate` and `Publish Preview`. The first is triggered by `pull_request` and uploads an artifact. The second is triggered by `workflow_run`, downloads the upstream artifact and has a later script execution step.

```
.github/workflows/validate.yml [pull_request]
      --> actions/upload-artifact
      --> workflow_run: Publish Preview
      --> actions/download-artifact
      --> python output/publish.py [contents: write]
```

The scanner emits **TG009** with a five-node explanation: source workflow, upload step, consumer trigger, download step and subsequent execution-like step. It **does not prove** the Python command executes downloaded code or that the upstream artifact is attacker-controlled in a given repository; developers must inspect the real artifact path and trust policy.

Samples are in [`examples/`](examples/), and formal rule conditions and remediation in [`docs/RULES.md`](docs/RULES.md).

## Report schema and interpretation

JSON includes `schema_version`, `tool`, `findings[]`, `edges[]`, and `summary`. Each finding identifies a rule, severity, workflow path, job, step ordinal, evidence, actionable remediation, a shortened SHA-256 fingerprint and optional cross-workflow `trace[]`. All output is deterministic for identical inputs. The SARIF `level` uses `error` for high/critical, `warning` for medium and `note` for low/info. **Line locations default to 1** because source range tracking is not yet implemented.

Baseline comparison relies on exact fingerprints. It tracks newly introduced vs resolved findings; it does not transfer approvals across arbitrary changes to source evidence. Changing a workflow path, job name or evidence text can produce a new fingerprint.

## Security rules

Nine rules: **TG001** implicit token permissions; **TG002** explicit write privileges; **TG003** privileged trigger with write token/secrets; **TG004** lower-trust events on self-hosted runners; **TG005** unpinned actions; **TG006** direct expression injection into `run`; **TG007** privileged PR checkout; **TG008** persisted checkout credentials; **TG009** cross-workflow artifact path. Read [`docs/RULES.md`](docs/RULES.md) for severity, conditions, false positives and remediation.

## Development and testing

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m coverage run --branch -m unittest discover -s tests
python -m coverage report -m
python -m build
```

GitHub Actions CI runs Python **3.11 / 3.12 / 3.13** on Ubuntu, Windows and macOS. The workflow uses a read-only token, immutable action pins and no untrusted checkout. The release automation will publish versioned source and checksum **only after a successful CI run** on the main branch. See [`docs/TEST_MATRIX.md`](docs/TEST_MATRIX.md).

## Architecture and security boundaries

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — parsing, workflow/event graph, stable evidence and output contracts.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — attacker control assumptions, modeled boundaries, residual risk and non-goals.
- [`docs/RULES.md`](docs/RULES.md) — detailed detection and remediation catalog.
- [`SECURITY.md`](SECURITY.md) — responsible security disclosure.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — reproducible test and contribution process.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.

**Important limitations:** This is static heuristic analysis, not a full workflow execution engine; it does not parse all external reusable workflows, infer exact real-world privilege grants or independently validate action SHA provenance. Dynamic `if:` logic, artifact-to-command data flow and third-party action internals are outside the model. A zero-finding report is not a security certification. See the threat model for detailed limitations.

## Responsible use

Analyze only your own or authorized workflow sources. No active exploitation, credential extraction, scanning of third-party endpoints, or cluster calls are performed. Example YAML is synthetic. Avoid uploading workflow sources containing proprietary data to untrusted services. Always evaluate important findings manually.

## References

- [GitHub Actions — Script injections](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub Actions — Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Actions — Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [OpenSSF — Mitigating Attack Vectors in GitHub Workflows](https://openssf.org/blog/2024/08/12/mitigating-attack-vectors-in-github-workflows/)
- [Zizmor](https://docs.zizmor.sh/) — complementary workflow security scanner
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)

These references inform the project design; they do not imply any certification, endorsement or formal security audit.

## License

MIT — © 2026 Felipe Watter. See [`LICENSE`](LICENSE).
