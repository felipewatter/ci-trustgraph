# Changelog

## [1.0.2] — 2026-11-09

### Changed
- Updated SHA-pinned GitHub Actions `setup-python` from v5.6.0 to v7.1.0 in CI.
- Published the verified `main` revision as an immutable maintenance release; no analyzer rule changes.

## [1.0.1] — 2026-11-07

### Changed
- Updated build dependencies and SHA-pinned checkout action; strengthened CI trust-boundary regression tests.

All notable changes are recorded here. [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style.

## [1.0.0] — 2026-11-01

### Added
- Bounded, offline YAML ingestion with duplicate-key and alias rejection.
- Nine actionable rules, including a cross-workflow artifact path heuristic.
- Security findings with stable SHA-256 fingerprints, human-readable trust traces, and severity.
- Reproducible JSON, SARIF 2.1.0, graph export, and baseline comparison.
- Unit tests, CI on 3 operating systems and 3 Python versions, threat model and security policy.
