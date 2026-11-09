# CI TrustGraph v1.0.2

Maintenance release to synchronize the published package with the latest CI-verified `main` revision.

- Updated SHA-pinned `actions/setup-python` to v7.1.0.
- Preserved existing offline trust-boundary detection, reporting and API behavior.
- Built and verified wheel, sdist and SHA-256 checksums from the exact passing CI commit.

The previous v1.0.1 release remains immutable. The analyzer is heuristic; findings require human review.
