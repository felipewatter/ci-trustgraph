# CI TrustGraph v1.0.0

Initial public release of an **offline GitHub Actions cross-workflow trust-boundary analyzer**.

- Nine explainable security checks: workflow token privileges, untrusted expression interpolation, self-hosted runner exposure, remote action pinning and PR-controlled checkout of privileged workflows.
- **Cross-workflow trust tracing (TG009)** links potentially untrusted artifacts across an upstream uploader and a privileged downstream consumer, providing a reproducible evidence path.
- Text, JSON, SARIF 2.1.0, graph JSON, and security regression baselines.
- Safe YAML ingestion with duplicate-key, alias and symlink rejection plus bounded files/nodes.
- Python 3.11+ packaged CLI, extensive tests, and multi-OS GitHub Actions CI.

**Scope:** static heuristic analysis. Findings can overapproximate real attack paths, and absence of findings is not proof of safety. Read README, THREAT_MODEL and SECURITY before operating in production.
