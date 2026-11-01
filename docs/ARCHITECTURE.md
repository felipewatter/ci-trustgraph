# Architecture

## Objective

CI TrustGraph models selected security-relevant relationships from local GitHub Actions workflow declarations. Unlike full program analysis, it does **not** prove that arbitrary shell commands use downloaded artifacts. Its result is evidence-based prioritization of potentially hazardous **trust boundaries**.

## Data flow

```
.github/workflows/*.{yml,yaml}
              |
       bounded SafeLoader
              |
    immutable Workflow objects
              |
     +- local rule checks -----------+
     |                               |
     +-- workflow name joins --------+--> Finding[] (rule/severity/evidence/trace)
           |                                |
    upload-artifact + workflow_run +        +--> text / JSON / SARIF
    download-artifact + subsequent run      +--> stable fingerprint / baseline diff
           |
        Edge[] --> graph JSON
```

## Semantic boundaries

- **Workflow**: path, declared name, event triggers and jobs. Equal names may produce multiple conservative candidates.
- **Job**: permissions can override workflow-wide permissions. Omitted permissions are treated as unknown, *not* automatically writable.
- **Step**: order-aware detection of download followed by broad execution-command heuristics.
- **Cross-workflow join**: requires a workflow_run consuming a named producer whose event is potentially untrusted and which uploads artifacts. Does not simulate runtime control flow, artifacts provenance, conditions or expression evaluation.
- **Report**: deterministic sorting and SHA-256-derived finding fingerprints for easy baseline comparison.

## Limits

Per-workflow hard cap 512 KiB; at most 200 workflow files; YAML node cap 40,000; YAML aliases and duplicate keys rejected; symlink inputs rejected. These limits reduce accidental resource exhaustion but do not substitute OS resource limits or a sandbox.

## Output contracts

`report.schema_version=1.0`; `findings[]` contains `rule_id`, `severity`, `path`, `job`, `step`, `message`, `evidence`, `remediation`, `trace`, and `fingerprint`; `edges[]` contains `source`, `target`, and `relation`. SARIF 2.1.0 uses path-based locations at line 1 (not precise source locations) and fingerprints for cross-run matching. Stable fingerprints deliberately exclude descriptive prose but include evidence text; changing the expression or referenced action can change a fingerprint.
