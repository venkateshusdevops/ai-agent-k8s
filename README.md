# ai-agent-k8s

A **semi-autonomous Kubernetes remediation agent**. It investigates incidents on its own, but never changes the cluster without a signed human approval. Reasoning and embeddings run on **AWS Bedrock**; runbooks are retrieved with **RAG**.

## Flow

```
incident ─► RAG (runbooks + Bedrock KB) ─► evidence loop (read-only tools, bounded)
        ─► structured plan (forced tool call) ─► policy engine (deterministic)
        ─► HIL approval (signed, expiring, bound to plan hash)
        ─► server-side dry-run ─► execute ─► verify rollout ─► undo/escalate ─► audit
```

| Stage | Module | Notes |
|---|---|---|
| Plan | `agent.py` | Evidence IDs (`E1…`) must back the root cause; low confidence or fixes needing manifest changes -> **escalate**, no steps |
| Evidence | `k8s_tools.ReadTools` | pods, describe, events, logs, deployment, rollout history, top, nodes. Namespace-scoped, redacted, truncated. No Secrets, no env values |
| Access | `deploy/rbac.yaml` | Cluster-wide read (no Secrets); write verbs only via per-namespace Role (patch deployments, delete pods) |
| HIL | `hil.py` | CLI or file-based async approver; HMAC-signed, TTL, bound to exact plan hash; high-risk steps need typed confirmation |
| RAG | `rag.py` | Local Titan-embedded runbook index + optional Bedrock Knowledge Base (`BEDROCK_KB_ID`) |
| Bedrock | `bedrock.py` | Converse API (tool use), Titan Embeddings v2, optional Guardrail |
| Audit | `audit.py` | Hash-chained JSONL; `k8s-agent verify-audit` detects tampering |

## Security design

- **LLM proposes, code disposes**: `policy.py` allowlists actions, enforces namespace scope, protected namespaces, replica bounds, max steps, and scale delta. The model cannot add new verbs.
- **Prompt-injection defense**: logs/events/KB text are treated as untrusted data in system prompts; the model has no write tools during investigation, and plans are schema-forced.
- **Secrets**: `redact.py` scrubs keys, tokens, JWTs, passwords and URL creds before anything reaches the LLM or audit log.
- **Blast radius**: approvals are per-step; `delete_pod` refuses uncontrolled pods; scale auto-undoes if rollout is unhealthy.
- **Identity**: IRSA role with only `bedrock:InvokeModel`/`Retrieve` (`deploy/iam-policy.json`); non-root, read-only-rootfs pod, restricted egress.
- **Production hardening**: the HMAC secret is shared between agent and approver. In production, move approvals to a separate trust boundary (e.g. Slack/SSO app signing with an asymmetric key) behind the same `request()` interface.

## Quick start

```bash
pip install -e ".[dev]"
cp .env.example .env && set -a && . ./.env && set +a
pytest                                   # policy, redaction, approval and audit tests
k8s-agent index                          # embed runbooks/ with Titan
k8s-agent investigate "web pods restarting in apps" -n apps -w web   # read-only
k8s-agent fix "web pods restarting in apps" -n apps -w web          # with HIL
# async approvals:  APPROVER=file k8s-agent fix ...   then   k8s-agent approve --plan-hash <h> --steps 0
k8s-agent verify-audit
```

Enable model access for your chosen Claude model and Titan Embeddings in the Bedrock console, then set `BEDROCK_MODEL_ID` to an inference profile or model ID available in your region.

## Extending

- New actions: add to `policy.RISK`, `WriteActions.execute`, `PLAN_SCHEMA` enum, and the RBAC Role.
- New KB content: drop `.md` into `runbooks/` and re-run `k8s-agent index`; `LocalKB.remember()` can persist approved fixes as learned runbooks.
- Triggers: wire Alertmanager/EventBridge to `investigate` for auto-triage, keeping `fix` human-gated.
