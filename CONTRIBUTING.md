# Contributing

Contributions are welcome through issues and pull requests. Discuss broad rule additions before implementation. Include reproduction YAML, expected risk, remediation guidance and negative cases. Prefer deterministic tests to relying on network or timing.

1. Create a Python 3.11+ environment, `python -m pip install -e .`.
2. Run `python -m unittest discover -s tests -v` and `python -m compileall -q src tests`.
3. Add tests for privilege boundaries, safe alternatives, malformed data, and stable output.
4. Do not commit credentials, sensitive configs, or real-world victim examples. Keep the default operation offline.
5. Avoid disabling rules to make example workflows pass. Explain false positives or add precise refinements.

Use English for identifiers, documentation and CLI text so maintainers can collaborate internationally. The repository maintainer reviews security-sensitive changes.
