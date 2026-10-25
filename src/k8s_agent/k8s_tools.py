"""Kubernetes access split in two: ReadTools (evidence) and WriteActions (approved remediation)."""
from __future__ import annotations
import datetime as dt
import json
import time

from kubernetes import client, config as kconfig

from .models import Step
from .policy import Policy
from .redact import redact

MAX_CHARS = 6000


def load_clients():
    try:
        kconfig.load_incluster_config()
    except kconfig.ConfigException:
        kconfig.load_kube_config()
    return client.CoreV1Api(), client.AppsV1Api(), client.CustomObjectsApi()


def _clip(s: str) -> str:
    s = redact(s)
    return s if len(s) <= MAX_CHARS else s[:MAX_CHARS] + f"\n...[truncated {len(s) - MAX_CHARS} chars]"


def _cstate(c) -> dict:
    st, last = c.state, (c.last_state.terminated if c.last_state else None)
    if st.running:
        state = "running"
    elif st.waiting:
        state = f"waiting:{st.waiting.reason}"
    elif st.terminated:
        state = f"terminated:{st.terminated.reason}/exit{st.terminated.exit_code}"
    else:
        state = "unknown"
    return {"name": c.name, "ready": c.ready, "restarts": c.restart_count, "state": state,
            "last_terminated": f"{last.reason}/exit{last.exit_code}" if last else None, "image": c.image}


def _obj(name, desc, props, required, fn):
    return {"name": name, "description": desc, "fn": fn,
            "schema": {"type": "object", "properties": props, "required": required}}


class ReadTools:
    """Read-only. Never touches Secrets or ConfigMap values; env var values are never returned."""

    def __init__(self, policy: Policy):
        self.core, self.apps, self.custom = load_clients()
        self.policy = policy
        ns = {"namespace": {"type": "string"}}
        self.tools = {t["name"]: t for t in [
            _obj("list_pods", "List pods with phase, readiness and restarts.",
                 {**ns, "label_selector": {"type": "string"}}, ["namespace"], self.list_pods),
            _obj("describe_pod", "Container states, last termination reasons, resources, conditions.",
                 {**ns, "name": {"type": "string"}}, ["namespace", "name"], self.describe_pod),
            _obj("get_events", "Recent events in a namespace, optionally for one object.",
                 {**ns, "object_name": {"type": "string"}}, ["namespace"], self.get_events),
            _obj("get_logs", "Tail logs (redacted). Use previous=true for crashed containers.",
                 {**ns, "pod": {"type": "string"}, "container": {"type": "string"},
                  "previous": {"type": "boolean"}, "tail_lines": {"type": "integer"}},
                 ["namespace", "pod"], self.get_logs),
            _obj("get_deployment", "Deployment spec/status summary.",
                 {**ns, "name": {"type": "string"}}, ["namespace", "name"], self.get_deployment),
            _obj("get_rollout_history", "ReplicaSet revisions and images for a deployment.",
                 {**ns, "name": {"type": "string"}}, ["namespace", "name"], self.get_rollout_history),
            _obj("top_pods", "CPU/memory usage from metrics-server.", ns, ["namespace"], self.top_pods),
            _obj("get_nodes", "Node conditions and allocatable resources.", {}, [], self.get_nodes),
        ]}

    def tool_config(self) -> dict:
        return {"tools": [{"toolSpec": {"name": t["name"], "description": t["description"],
                                        "inputSchema": {"json": t["schema"]}}} for t in self.tools.values()]}

    def call(self, name: str, args: dict) -> str:
        if name not in self.tools:
            raise ValueError(f"unknown tool {name}")
        ns = args.get("namespace")
        if ns is not None and not self.policy.can_read(ns):
            raise PermissionError(f"namespace '{ns}' is not readable")
        return _clip(self.tools[name]["fn"](**args))

    # --- implementations ---
    def list_pods(self, namespace, label_selector=None):
        pods = self.core.list_namespaced_pod(namespace, label_selector=label_selector or "").items
        rows = []
        for p in pods:
            cs = p.status.container_statuses or []
            rows.append(f"{p.metadata.name} phase={p.status.phase} ready={sum(c.ready for c in cs)}/{len(cs)} "
                        f"restarts={sum(c.restart_count for c in cs)} reason={p.status.reason or ''}")
        return "\n".join(rows) or "no pods"

    def describe_pod(self, namespace, name):
        p = self.core.read_namespaced_pod(name, namespace)
        return json.dumps({
            "node": p.spec.node_name, "phase": p.status.phase,
            "owner": [(o.kind, o.name) for o in p.metadata.owner_references or []],
            "conditions": [(c.type, c.status, c.reason, c.message) for c in p.status.conditions or [] if c.status != "True"],
            "containers": [_cstate(c) for c in p.status.container_statuses or []],
            "resources": {c.name: {"requests": c.resources.requests, "limits": c.resources.limits}
                          for c in p.spec.containers},
        }, default=str, indent=1)

    def get_events(self, namespace, object_name=None):
        sel = f"involvedObject.name={object_name}" if object_name else None
        ev = self.core.list_namespaced_event(namespace, field_selector=sel).items
        ev.sort(key=lambda e: e.last_timestamp or e.event_time or e.metadata.creation_timestamp)
        return "\n".join(f"{e.type} {e.reason} {e.involved_object.kind}/{e.involved_object.name}: "
                         f"{e.message} (x{e.count or 1})" for e in ev[-30:]) or "no events"

    def get_logs(self, namespace, pod, container=None, previous=False, tail_lines=150):
        return self.core.read_namespaced_pod_log(pod, namespace, container=container, previous=bool(previous),
                                                 tail_lines=min(int(tail_lines), 300))

    def get_deployment(self, namespace, name):
        d = self.apps.read_namespaced_deployment(name, namespace)
        return json.dumps({
            "replicas": d.spec.replicas, "status": {"ready": d.status.ready_replicas,
            "available": d.status.available_replicas, "updated": d.status.updated_replicas},
            "strategy": d.spec.strategy.type,
            "conditions": [(c.type, c.status, c.reason, c.message) for c in d.status.conditions or []],
            "containers": [{"name": c.name, "image": c.image,
                            "resources": {"requests": c.resources.requests, "limits": c.resources.limits},
                            "readiness": bool(c.readiness_probe), "liveness": bool(c.liveness_probe)}
                           for c in d.spec.template.spec.containers],
            "selector": d.spec.selector.match_labels,
        }, default=str, indent=1)

    def _replicasets(self, namespace, name):
        d = self.apps.read_namespaced_deployment(name, namespace)
        sel = ",".join(f"{k}={v}" for k, v in d.spec.selector.match_labels.items())
        rs = [r for r in self.apps.list_namespaced_replica_set(namespace, label_selector=sel).items
              if any(o.uid == d.metadata.uid for o in r.metadata.owner_references or [])]
        rs.sort(key=lambda r: int(r.metadata.annotations.get("deployment.kubernetes.io/revision", 0)), reverse=True)
        return rs

    def get_rollout_history(self, namespace, name):
        return "\n".join(f"revision={r.metadata.annotations.get('deployment.kubernetes.io/revision')} "
                         f"images={[c.image for c in r.spec.template.spec.containers]} "
                         f"replicas={r.status.replicas} created={r.metadata.creation_timestamp}"
                         for r in self._replicasets(namespace, name))

    def top_pods(self, namespace):
        try:
            m = self.custom.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", namespace, "pods")
        except Exception as e:  # metrics-server may be absent
            return f"metrics unavailable: {e}"
        return "\n".join(f"{i['metadata']['name']} " + " ".join(f"{c['name']}:cpu={c['usage']['cpu']},mem={c['usage']['memory']}"
                         for c in i["containers"]) for i in m["items"])

    def get_nodes(self):
        return "\n".join(f"{n.metadata.name} " + ",".join(f"{c.type}={c.status}" for c in n.status.conditions)
                         + f" alloc={n.status.allocatable}" for n in self.core.list_node().items)


class WriteActions:
    """Mutations. Each runs server-side dry-run first; only called after policy + signed approval."""

    def __init__(self, policy: Policy, verify_timeout: int = 180):
        self.core, self.apps, _ = load_clients()
        self.policy, self.verify_timeout = policy, verify_timeout

    def execute(self, s: Step, dry_run: bool) -> tuple[str, callable | None]:
        """Returns (message, undo_callable|None)."""
        dr = "All" if dry_run else None
        ns, t = s.namespace, s.target
        if s.action == "restart_deployment":
            body = {"spec": {"template": {"metadata": {"annotations": {
                "kubectl.kubernetes.io/restartedAt": dt.datetime.now(dt.timezone.utc).isoformat()}}}}}
            self.apps.patch_namespaced_deployment(t, ns, body, dry_run=dr)
            return f"restarted deployment {ns}/{t}", None
        if s.action == "scale_deployment":
            cur = self.apps.read_namespaced_deployment_scale(t, ns).spec.replicas
            new = s.params["replicas"]
            self.policy.check_scale_delta(cur, new)
            self.apps.patch_namespaced_deployment_scale(t, ns, {"spec": {"replicas": new}}, dry_run=dr)
            undo = lambda: self.apps.patch_namespaced_deployment_scale(t, ns, {"spec": {"replicas": cur}})
            return f"scaled {ns}/{t} {cur}->{new}", undo
        if s.action == "rollback_deployment":
            from .k8s_tools import ReadTools  # reuse RS discovery
            rs = ReadTools.__new__(ReadTools)
            rs.apps = self.apps
            revs = rs._replicasets(ns, t)
            want = s.params.get("to_revision")
            target = next((r for r in revs if str(r.metadata.annotations.get("deployment.kubernetes.io/revision")) == str(want)),
                          revs[1] if len(revs) > 1 else None)
            if not target:
                raise RuntimeError("no previous revision to roll back to")
            tpl = client.ApiClient().sanitize_for_serialization(target.spec.template)
            tpl["metadata"]["labels"].pop("pod-template-hash", None)
            self.apps.patch_namespaced_deployment(t, ns, {"spec": {"template": tpl}}, dry_run=dr)
            return f"rolled back {ns}/{t} to revision {target.metadata.annotations.get('deployment.kubernetes.io/revision')}", None
        if s.action == "delete_pod":
            p = self.core.read_namespaced_pod(t, ns)
            if not any(o.controller for o in p.metadata.owner_references or []):
                raise PermissionError("refusing to delete a pod with no controller (it would not be recreated)")
            self.core.delete_namespaced_pod(t, ns, dry_run=dr)
            return f"deleted pod {ns}/{t}", None
        raise ValueError(s.action)

    def wait_healthy(self, namespace: str, deployment: str) -> bool:
        end = time.time() + self.verify_timeout
        while time.time() < end:
            d = self.apps.read_namespaced_deployment(deployment, namespace)
            want, st = d.spec.replicas or 0, d.status
            if (st.observed_generation or 0) >= d.metadata.generation and (st.updated_replicas or 0) == want \
                    and (st.available_replicas or 0) == want and not st.unavailable_replicas:
                return True
            time.sleep(5)
        return False
