from __future__ import annotations
import argparse
import sys

from .audit import verify_chain
from .config import Config
from .hil import render_plan, write_decision


def _build(cfg: Config):
    from .agent import Agent
    from .audit import Audit
    from .bedrock import Bedrock
    from .hil import make_approver
    from .k8s_tools import ReadTools, WriteActions
    from .policy import Policy
    from .rag import Retriever
    llm, policy = Bedrock(cfg), Policy(cfg)
    return Agent(cfg, llm, Retriever(cfg, llm), ReadTools(policy), WriteActions(policy, cfg.verify_timeout),
                 policy, make_approver(cfg), Audit(cfg.audit_path)), llm


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="k8s-agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("investigate", "fix"):
        p = sub.add_parser(name, help="investigate = read-only plan; fix = plan + HIL approval + execute")
        p.add_argument("incident")
        p.add_argument("-n", "--namespace")
        p.add_argument("-w", "--workload")
    sub.add_parser("index", help="(re)build the local runbook vector index")
    a = sub.add_parser("approve", help="issue a signed approval for a pending plan (file approver)")
    a.add_argument("--plan-hash", required=True)
    a.add_argument("--steps", required=True, help="comma-separated step indexes")
    v = sub.add_parser("verify-audit")
    v.add_argument("--path")
    args = ap.parse_args(argv)
    cfg = Config.from_env()

    if args.cmd == "approve":
        print(write_decision(cfg, args.plan_hash, [int(x) for x in args.steps.split(",")]))
        return 0
    if args.cmd == "verify-audit":
        ok = verify_chain(args.path or cfg.audit_path)
        print("audit chain OK" if ok else "AUDIT CHAIN BROKEN")
        return 0 if ok else 2
    if args.cmd == "index":
        from .bedrock import Bedrock
        from .rag import LocalKB
        print(f"indexed {LocalKB(cfg, Bedrock(cfg)).build()} chunks")
        return 0

    from .models import Incident
    agent, _ = _build(cfg)
    rep = agent.run(Incident(args.incident, args.namespace, args.workload), execute=args.cmd == "fix")
    print(f"\n== Evidence ({len(rep.evidence)} calls) ==")
    for e in rep.evidence:
        print(f"[{e.id}] {e.tool} {e.args}")
    print(f"KB sources: {', '.join(rep.kb_sources)}")
    if rep.plan:
        print(render_plan(rep.plan))
        if rep.plan.escalate:
            print(f"ESCALATE: {rep.plan.escalate_reason}")
    for v_ in rep.violations:
        print(f"POLICY: {v_}")
    for x in rep.executed:
        print(f"EXEC: {x}")
    print(f"\nOutcome: {rep.outcome}")
    return 0 if rep.outcome in ("resolved", "escalated", "not_executed") else 1


if __name__ == "__main__":
    sys.exit(main())
