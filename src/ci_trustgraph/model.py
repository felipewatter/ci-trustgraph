"""Immutable data structures for deterministic security evidence."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from hashlib import sha256
import json
from typing import Any

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    job: str
    step: int
    message: str
    evidence: str
    remediation: str
    trace: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        # Stable across prose changes, does not store untrusted content.
        identity = [self.rule_id, self.path, self.job, self.step, self.evidence]
        return sha256(json.dumps(identity, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "fingerprint": self.fingerprint}


@dataclass(frozen=True, slots=True)
class Workflow:
    path: str
    name: str
    events: frozenset[str]
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    target: str
    relation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
