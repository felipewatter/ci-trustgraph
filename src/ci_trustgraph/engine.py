"""Explainable cross-workflow CI trust-boundary heuristics."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any
from .model import Edge, Finding, Workflow

SHA40 = re.compile(r'^[0-9a-fA-F]{40}$')
EXPR = re.compile(r'\$\{\{(.*?)\}\}', re.DOTALL)
UNTRUSTED = re.compile(
    r'\b(?:github\.head_ref|github\.event\.(?:pull_request\.(?:title|body|head\.(?:ref|label))|'
    r'issue\.(?:title|body)|comment\.body|discussion\.(?:title|body)|'
    r'head_commit\.message|commits\[|workflow_run\.head_branch))\b', re.I)
PR_HEAD = re.compile(r'github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref', re.I)
WRITE = re.compile(r'(^write-all$|^write$)', re.I)
DOWNLOAD = re.compile(r'(^|/)download-artifact@', re.I)
UPLOAD = re.compile(r'(^|/)upload-artifact@', re.I)
EXECUTE = re.compile(r'\b(?:bash|sh|python|node|npm|make|source|\.\s|chmod|pwsh|powershell|docker\s+run)\b', re.I)


def _events(flow: Workflow) -> set[str]:
    return set(flow.events)


def _jobs(flow: Workflow):
    return [(str(k), v) for k, v in flow.raw['jobs'].items() if isinstance(v, dict)]


def _steps(job: dict):
    steps = job.get('steps', [])
    return list(enumerate(steps, 1)) if isinstance(steps, list) else []


def _permission(perms: Any) -> bool:
    if isinstance(perms, str):
        return bool(WRITE.search(perms))
    return isinstance(perms, dict) and any(v == 'write' for v in perms.values())


def _writable(job: dict, flow: Workflow) -> bool:
    # Omitted permissions inherit repository/org defaults: not assumed safe.
    return _permission(job.get('permissions', flow.raw.get('permissions')))


def _unknown_permissions(job: dict, flow: Workflow) -> bool:
    return 'permissions' not in job and 'permissions' not in flow.raw


def _job_secrets(job: dict) -> bool:
    for step in job.get('steps', []):
        if isinstance(step, dict) and 'secrets.' in str(step):
            return True
    return 'secrets.' in str(job.get('env', {}))


def _issue(rule: str, severity: str, flow: Workflow, job: str, step: int, message: str,
           evidence: str, remediation: str, trace: tuple[str, ...] = ()) -> Finding:
    return Finding(rule, severity, flow.path, job, step, message, evidence, remediation, trace)


def _triggers_run(flow: Workflow) -> list[str]:
    cfg = flow.raw.get('on', {})
    if not isinstance(cfg, dict):
        return []
    wr = cfg.get('workflow_run', {})
    if not isinstance(wr, dict):
        return []
    names = wr.get('workflows', [])
    return [n for n in names if isinstance(n, str)] if isinstance(names, list) else []


def _untrusted_producer(flow: Workflow) -> bool:
    return bool(_events(flow) & {'pull_request', 'pull_request_target', 'issue_comment', 'discussion', 'workflow_dispatch'})


def _artifact_uploader(flow: Workflow) -> bool:
    return any(UPLOAD.search(str(step.get('uses', ''))) for _, job in _jobs(flow) for _, step in _steps(job) if isinstance(step, dict))


def _artifact_consumer(job: dict) -> tuple[int, int] | None:
    indexes = [(n, step) for n, step in _steps(job) if isinstance(step, dict)]
    downloads = [n for n, s in indexes if DOWNLOAD.search(str(s.get('uses', '')))]
    if not downloads:
        return None
    first = min(downloads)
    executes = [n for n, s in indexes if n > first and isinstance(s.get('run'), str) and EXECUTE.search(s['run'])]
    if not executes:
        return None
    return first, min(executes)


def _is_sha_pinned(uses: str) -> bool:
    if uses.startswith('./'):
        return True
    if uses.startswith('docker://'):
        return '@sha256:' in uses and bool(re.search(r'@sha256:[a-fA-F0-9]{64}$', uses))
    if '@' not in uses:
        return False
    ref = uses.rsplit('@', 1)[1]
    return bool(SHA40.fullmatch(ref))


def scan(flows: list[Workflow]) -> tuple[list[Finding], list[Edge]]:
    findings: list[Finding] = []
    edges: list[Edge] = []
    by_name: dict[str, list[Workflow]] = {}
    for flow in flows:
        by_name.setdefault(flow.name, []).append(flow)
        privileged = bool(_events(flow) & {'pull_request_target', 'workflow_run', 'issue_comment'})
        for jid, job in _jobs(flow):
            edges.append(Edge(flow.path, f'{flow.path}#{jid}', 'contains_job'))
            write = _writable(job, flow)
            unknown = _unknown_permissions(job, flow)
            if unknown:
                findings.append(_issue('TG001', 'medium', flow, jid, 0,
                    'Token permissions are implicit; effective privileges depend on repository defaults.',
                    'permissions: omitted', 'Set explicit least-privilege permissions at workflow or job scope.'))
            if write:
                findings.append(_issue('TG002', 'medium', flow, jid, 0,
                    'Job receives an explicitly writable GITHUB_TOKEN.',
                    'permissions: write', 'Restrict permissions to the exact required scopes.'))
            if privileged and (write or _job_secrets(job)):
                findings.append(_issue('TG003', 'high' if 'pull_request_target' in flow.events or ('issue_comment' in flow.events and _job_secrets(job)) else 'medium', flow, jid, 0,
                    'Privileged event combined with write token or referenced secrets.',
                    ','.join(sorted(_events(flow))),
                    'Split untrusted processing into read-only workflows and validate provenance before privileged operations.'))
            runner = job.get('runs-on')
            if _events(flow) & {'pull_request', 'pull_request_target', 'issue_comment'} and 'self-hosted' in str(runner):
                findings.append(_issue('TG004', 'high', flow, jid, 0,
                    'Potentially untrusted event on a self-hosted runner.', 'self-hosted',
                    'Use isolated ephemeral runners with restricted credentials or hosted runners.'))
            for n, step in _steps(job):
                if not isinstance(step, dict):
                    continue
                uses = step.get('uses', '')
                if isinstance(uses, str) and uses and not _is_sha_pinned(uses):
                    findings.append(_issue('TG005', 'medium', flow, jid, n,
                        'Remote action is not pinned to an immutable commit/digest.', uses[:160],
                        'Pin actions to a verified full commit SHA; review updates.'))
                run = step.get('run')
                if isinstance(run, str):
                    for expression in EXPR.findall(run):
                        if UNTRUSTED.search(expression):
                            findings.append(_issue('TG006', 'high', flow, jid, n,
                                'Attacker-influenced GitHub expression interpolated directly into a runner script.',
                                expression.strip()[:160],
                                'Pass the value via an environment variable and quote it as data; avoid interpolation in executable scripts.'))
                if privileged and isinstance(uses, str) and uses.lower().startswith('actions/checkout@'):
                    with_cfg = step.get('with', {})
                    if isinstance(with_cfg, dict) and PR_HEAD.search(str(with_cfg.get('ref', ''))):
                        severity = 'critical' if write or _job_secrets(job) else 'high'
                        findings.append(_issue('TG007', severity, flow, jid, n,
                            'Privileged workflow checks out pull-request-controlled revision.',
                            str(with_cfg.get('ref', ''))[:160],
                            'Do not execute untrusted PR code in privileged workflows; separate trust domains.'))
                if uses and isinstance(uses, str) and uses.lower().startswith('actions/checkout@'):
                    with_cfg = step.get('with', {})
                    if isinstance(with_cfg, dict) and str(with_cfg.get('persist-credentials', 'true')).lower() != 'false' and (write or privileged):
                        findings.append(_issue('TG008', 'low', flow, jid, n,
                            'Checkout persists GitHub credentials in the working directory by default.',
                            'persist-credentials: true/default',
                            'Set persist-credentials: false where git push is unnecessary.'))
    # Cross-workflow graph: matching names + producer uploads + consumer downloads and executes.
    for flow in flows:
        if 'workflow_run' not in flow.events:
            continue
        for name in _triggers_run(flow):
            for prod in by_name.get(name, []):
                edges.append(Edge(prod.path, flow.path, 'workflow_run'))
                if not (_untrusted_producer(prod) and _artifact_uploader(prod)):
                    continue
                for jid, job in _jobs(flow):
                    indexes = _artifact_consumer(job)
                    if indexes is None:
                        continue
                    download, execution = indexes
                    can_access = _writable(job, flow) or _job_secrets(job)
                    trace = (f'{prod.path} ({prod.name}): untrusted event',
                             'upload-artifact', f'{flow.path}: workflow_run',
                             f'{jid}: download-artifact step {download}', f'{jid}: execution step {execution}')
                    findings.append(_issue('TG009', 'critical' if can_access else 'high', flow, jid, execution,
                        'Untrusted workflow may pass artifact content to an executing downstream workflow.',
                        f'{prod.path} -> {flow.path}',
                        'Treat downloaded artifacts as untrusted data; validate expected structure and never execute artifact-supplied code.', trace))
                    edges.append(Edge(prod.path, f'{flow.path}#{jid}', 'artifact_to_execution'))
    findings.sort(key=lambda f: (-{'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}[f.severity], f.path, f.job, f.step, f.rule_id, f.evidence))
    edges.sort(key=lambda e: (e.source, e.target, e.relation))
    return findings, edges
