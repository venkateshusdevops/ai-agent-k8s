"""Deterministic guardrails. The LLM proposes; this module disposes."""
from __future__ import annotations

from .config import Config
from .models import Plan, Step

# action -> risk tier. Anything not listed is rejected.
RISK = {
    "delete_pod": "low",            # controller-owned pods only (checked at execution)
    "restart_deployment": "medium",
    "scale_deployment": "medium",
    "rollback_deployment": "high",
}


class Policy:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def can_read(self, namespace: str) -> bool:
        return namespace in self.cfg.allowed_namespaces

    def can_write(self, namespace: str) -> bool:
        return namespace in self.cfg.allowed_namespaces and namespace not in self.cfg.protected_namespaces

    def validate_step(self, i: int, s: Step) -> list[str]:
        v = []
        if s.action not in RISK:
            return [f"step {i}: action '{s.action}' is not allowlisted"]
        if not self.can_write(s.namespace):
            v.append(f"step {i}: namespace '{s.namespace}' is not writable")
        if not s.target or "*" in s.target:
            v.append(f"step {i}: target must be a single named object")
        if s.action == "scale_deployment":
            r = s.params.get("replicas")
            if not isinstance(r, int) or not (0 <= r <= self.cfg.max_replicas):
                v.append(f"step {i}: replicas must be an int in [0,{self.cfg.max_replicas}]")
        return v

    def validate_plan(self, plan: Plan, known_evidence: set[str]) -> list[str]:
        v = []
        if len(plan.steps) > self.cfg.max_steps_per_plan:
            v.append(f"plan has {len(plan.steps)} steps (max {self.cfg.max_steps_per_plan})")
        if plan.confidence < self.cfg.min_confidence:
            v.append(f"confidence {plan.confidence:.2f} below {self.cfg.min_confidence}")
        if not plan.evidence_refs or not set(plan.evidence_refs) <= known_evidence:
            v.append("plan must cite evidence IDs that exist")
        for i, s in enumerate(plan.steps):
            v += self.validate_step(i, s)
        return v

    def check_scale_delta(self, current: int, new: int) -> None:
        if abs(new - current) > self.cfg.max_scale_delta:
            raise PermissionError(f"scale delta {abs(new - current)} exceeds {self.cfg.max_scale_delta}")
