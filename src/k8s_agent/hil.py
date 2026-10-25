"""Human-in-the-loop approval. Approvals are signed, expiring, and bound to an exact plan hash."""
from __future__ import annotations
import getpass
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass, asdict

from .config import Config
from .models import Plan
from .policy import RISK


def _sig(secret: str, h: str, approver: str, steps: list[int], issued: float, expires: float) -> str:
    payload = f"{h}|{approver}|{','.join(map(str, steps))}|{issued:.0f}|{expires:.0f}"
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


@dataclass
class Approval:
    plan_hash: str
    approver: str
    approved_steps: list[int]
    issued_at: float
    expires_at: float
    signature: str

    @classmethod
    def issue(cls, secret: str, plan_hash: str, approver: str, steps: list[int], ttl: int) -> "Approval":
        now = time.time()
        return cls(plan_hash, approver, steps, now, now + ttl,
                   _sig(secret, plan_hash, approver, steps, now, now + ttl))

    def verify(self, secret: str, plan: Plan) -> None:
        if self.plan_hash != plan.hash():
            raise PermissionError("approval does not match this plan (plan changed after approval)")
        if time.time() > self.expires_at:
            raise PermissionError("approval expired")
        good = _sig(secret, self.plan_hash, self.approver, self.approved_steps, self.issued_at, self.expires_at)
        if not hmac.compare_digest(good, self.signature):
            raise PermissionError("invalid approval signature")
        if any(i < 0 or i >= len(plan.steps) for i in self.approved_steps):
            raise PermissionError("approval references nonexistent steps")


def render_plan(plan: Plan) -> str:
    lines = [f"\nPLAN {plan.hash()}  confidence={plan.confidence:.2f}",
             f"Root cause: {plan.root_cause}", f"Evidence: {', '.join(plan.evidence_refs)}"]
    for i, s in enumerate(plan.steps):
        lines.append(f"  [{i}] ({RISK.get(s.action, '?').upper()}) {s.action} {s.namespace}/{s.target} "
                     f"{json.dumps(s.params)}\n      why: {s.rationale}\n      verify: {s.verify}")
    return "\n".join(lines)


class CLIApprover:
    """Interactive approval on a TTY. High-risk steps require typing the target name."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def request(self, plan: Plan) -> Approval | None:
        if not sys.stdin.isatty():
            print("Non-interactive session: refusing to auto-approve.")
            return None
        print(render_plan(plan))
        approved = []
        for i, s in enumerate(plan.steps):
            ans = input(f"Approve step [{i}] {s.action} {s.namespace}/{s.target}? [y/N] ").strip().lower()
            if ans != "y":
                continue
            if RISK[s.action] == "high" and input(f"HIGH RISK - type '{s.target}' to confirm: ").strip() != s.target:
                print("Confirmation mismatch; step skipped.")
                continue
            approved.append(i)
        if not approved:
            return None
        return Approval.issue(self.cfg.approval_secret, plan.hash(), getpass.getuser(), approved, self.cfg.approval_ttl)


class FileApprover:
    """Async approval: writes pending/<hash>.json, waits for a signed decision file created by
    `k8s-agent approve`. Swap for Slack/ServiceNow/SSO-backed approvers in production."""

    def __init__(self, cfg: Config, timeout: int = 900):
        self.cfg, self.timeout = cfg, timeout
        os.makedirs(os.path.join(cfg.approval_dir, "pending"), exist_ok=True)
        os.makedirs(os.path.join(cfg.approval_dir, "decisions"), exist_ok=True)

    def request(self, plan: Plan) -> Approval | None:
        h = plan.hash()
        with open(os.path.join(self.cfg.approval_dir, "pending", f"{h}.json"), "w") as f:
            f.write(plan.canonical())
        print(render_plan(plan))
        print(f"\nWaiting for: k8s-agent approve --plan-hash {h} --steps 0,1")
        path = os.path.join(self.cfg.approval_dir, "decisions", f"{h}.json")
        end = time.time() + self.timeout
        while time.time() < end:
            if os.path.exists(path):
                with open(path) as f:
                    d = json.load(f)
                return Approval(**d) if d.get("approved_steps") else None
            time.sleep(2)
        return None


def write_decision(cfg: Config, plan_hash: str, steps: list[int], approver: str | None = None) -> str:
    a = Approval.issue(cfg.approval_secret, plan_hash, approver or getpass.getuser(), steps, cfg.approval_ttl)
    path = os.path.join(cfg.approval_dir, "decisions", f"{plan_hash}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(asdict(a), f)
    return path


def make_approver(cfg: Config):
    return FileApprover(cfg) if cfg.approver == "file" else CLIApprover(cfg)
