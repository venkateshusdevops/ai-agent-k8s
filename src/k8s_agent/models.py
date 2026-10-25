from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, asdict


@dataclass
class Incident:
    text: str
    namespace: str | None = None
    workload: str | None = None


@dataclass
class Evidence:
    id: str
    tool: str
    args: dict
    output: str


@dataclass
class Step:
    action: str
    namespace: str
    target: str
    params: dict = field(default_factory=dict)
    rationale: str = ""
    verify: str = ""


@dataclass
class Plan:
    root_cause: str
    confidence: float
    evidence_refs: list[str]
    steps: list[Step]
    escalate: bool = False
    escalate_reason: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Plan":
        steps = [Step(**{k: v for k, v in s.items() if k in Step.__dataclass_fields__})
                 for s in d.get("steps", [])]
        return cls(
            root_cause=d.get("root_cause", ""),
            confidence=float(d.get("confidence", 0)),
            evidence_refs=list(d.get("evidence_refs", [])),
            steps=steps,
            escalate=bool(d.get("escalate", False)),
            escalate_reason=d.get("escalate_reason", ""),
        )

    def canonical(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def hash(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()[:16]


@dataclass
class Report:
    incident: Incident
    evidence: list[Evidence]
    kb_sources: list[str]
    plan: Plan | None
    violations: list[str]
    approved_steps: list[int]
    executed: list[dict]
    outcome: str  # escalated | rejected | not_executed | resolved | failed
