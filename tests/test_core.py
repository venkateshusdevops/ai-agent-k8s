import time
import pytest
from k8s_agent.audit import Audit, verify_chain
from k8s_agent.config import Config
from k8s_agent.hil import Approval
from k8s_agent.models import Plan, Step
from k8s_agent.policy import Policy
from k8s_agent.redact import redact


def plan(**kw):
    s = Step("restart_deployment", "apps", "web", {}, "r", "v")
    return Plan("rc", 0.9, ["E1"], [kw.get("step", s)])


def test_redact():
    t = "password=hunter2 key AKIAABCDEFGHIJKLMNOP Bearer abc.def postgres://u:pw@h/db"
    out = redact(t)
    for leak in ("hunter2", "AKIAABCDEFGHIJKLMNOP", "abc.def", ":pw@"):
        assert leak not in out


def test_policy_blocks_protected_and_unknown():
    p = Policy(Config(allowed_namespaces=["apps", "kube-system"], protected_namespaces=["kube-system"]))
    assert p.validate_plan(plan(), {"E1"}) == []
    bad = Step("restart_deployment", "kube-system", "coredns")
    assert any("not writable" in v for v in p.validate_plan(plan(step=bad), {"E1"}))
    assert any("allowlisted" in v for v in p.validate_plan(plan(step=Step("exec", "apps", "x")), {"E1"}))
    assert any("evidence" in v for v in p.validate_plan(plan(), {"E9"}))


def test_scale_bounds():
    p = Policy(Config())
    s = Step("scale_deployment", "apps", "web", {"replicas": 999})
    assert any("replicas" in v for v in p.validate_plan(plan(step=s), {"E1"}))
    with pytest.raises(PermissionError):
        p.check_scale_delta(2, 20)


def test_approval_bound_to_plan_and_signed():
    pl = plan()
    a = Approval.issue("s3cret", pl.hash(), "alice", [0], 60)
    a.verify("s3cret", pl)
    with pytest.raises(PermissionError):
        a.verify("wrong", pl)
    pl.steps[0].target = "other"           # plan mutated after approval
    with pytest.raises(PermissionError):
        a.verify("s3cret", pl)
    old = Approval.issue("s3cret", plan().hash(), "alice", [0], -1)
    with pytest.raises(PermissionError):
        old.verify("s3cret", plan())


def test_audit_chain_detects_tamper(tmp_path):
    path = str(tmp_path / "a.jsonl")
    a = Audit(path)
    a.log("x", v=1); a.log("y", v=2)
    assert verify_chain(path)
    txt = open(path).read().replace('"v": 1', '"v": 9')
    open(path, "w").write(txt)
    assert not verify_chain(path)
