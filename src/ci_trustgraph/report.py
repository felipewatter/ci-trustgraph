"""Stable machine-readable and human-readable report formats."""
import json
from collections import Counter
from .model import Finding, Edge


def result(findings: list[Finding], edges: list[Edge]) -> dict:
    return {"schema_version": "1.0", "tool": "ci-trustgraph", "findings": [f.to_dict() for f in findings],
            "edges": [e.to_dict() for e in edges], "summary": dict(sorted(Counter(f.severity for f in findings).items()))}


def render_text(findings: list[Finding], edges: list[Edge]) -> str:
    lines = [f'CI TrustGraph: {len(findings)} finding(s), {len(edges)} trust edge(s)']
    for f in findings:
        lines.append(f'[{f.severity.upper():8}] {f.rule_id} {f.path} job={f.job} step={f.step}: {f.message}')
        if f.trace:
            lines.append('    Trust path: ' + ' -> '.join(f.trace))
    return '\n'.join(lines) + '\n'


def render_sarif(findings: list[Finding]) -> dict:
    rule_ids = sorted({f.rule_id for f in findings})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "CI TrustGraph", "semanticVersion": "1.0.0",
                                        "rules": [{"id": k, "shortDescription": {"text": k}} for k in rule_ids]}},
                      "results": [{"ruleId": f.rule_id,
                                   "level": 'error' if f.severity in ('critical', 'high') else 'warning' if f.severity == 'medium' else 'note',
                                   "message": {"text": f.message + ' Remediation: ' + f.remediation},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": 1}}}],
                                   "partialFingerprints": {"ciTrustGraph/v1": f.fingerprint},
                                   "properties": {"security-severity": f.severity, "trace": list(f.trace), "job": f.job, "step": f.step}}
                                  for f in findings]}]}


def diff(baseline: list[dict], current: list[Finding]) -> dict:
    old = {str(x['fingerprint']): x for x in baseline}
    now = {x.fingerprint: x.to_dict() for x in current}
    return {"introduced": [now[k] for k in sorted(now.keys() - old.keys())],
            "resolved": [old[k] for k in sorted(old.keys() - now.keys())],
            "unchanged": len(now.keys() & old.keys())}
