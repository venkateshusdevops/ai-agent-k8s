from __future__ import annotations
import os
from dataclasses import dataclass, field


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Config:
    region: str = "us-east-1"
    model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    embed_model_id: str = "amazon.titan-embed-text-v2:0"
    kb_id: str = ""
    guardrail_id: str = ""
    guardrail_version: str = "1"
    allowed_namespaces: list[str] = field(default_factory=lambda: ["apps"])
    protected_namespaces: list[str] = field(
        default_factory=lambda: ["kube-system", "kube-public"]
    )
    max_steps_per_plan: int = 3
    max_replicas: int = 20
    max_scale_delta: int = 5
    min_confidence: float = 0.6
    max_evidence_steps: int = 10
    approval_secret: str = "change-me"
    approval_ttl: int = 900
    approver: str = "cli"
    audit_path: str = "./audit/audit.jsonl"
    runbook_dir: str = "./runbooks"
    index_path: str = "./.kb/index.json"
    approval_dir: str = "./.approvals"
    verify_timeout: int = 180

    @classmethod
    def from_env(cls) -> "Config":
        e = os.getenv
        return cls(
            region=e("AWS_REGION", cls.region),
            model_id=e("BEDROCK_MODEL_ID", cls.model_id),
            embed_model_id=e("BEDROCK_EMBED_MODEL_ID", cls.embed_model_id),
            kb_id=e("BEDROCK_KB_ID", ""),
            guardrail_id=e("BEDROCK_GUARDRAIL_ID", ""),
            guardrail_version=e("BEDROCK_GUARDRAIL_VERSION", "1"),
            allowed_namespaces=_list("ALLOWED_NAMESPACES", "apps"),
            protected_namespaces=_list("PROTECTED_NAMESPACES", "kube-system,kube-public"),
            max_steps_per_plan=int(e("MAX_STEPS_PER_PLAN", 3)),
            max_replicas=int(e("MAX_REPLICAS", 20)),
            max_scale_delta=int(e("MAX_SCALE_DELTA", 5)),
            min_confidence=float(e("MIN_CONFIDENCE", 0.6)),
            max_evidence_steps=int(e("MAX_EVIDENCE_STEPS", 10)),
            approval_secret=e("APPROVAL_HMAC_SECRET", "change-me"),
            approval_ttl=int(e("APPROVAL_TTL_SECONDS", 900)),
            approver=e("APPROVER", "cli"),
            audit_path=e("AUDIT_PATH", cls.audit_path),
            runbook_dir=e("RUNBOOK_DIR", cls.runbook_dir),
            index_path=e("INDEX_PATH", cls.index_path),
            approval_dir=e("APPROVAL_DIR", cls.approval_dir),
        )
