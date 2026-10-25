# Pending pods

## Diagnosis
`get_events` for FailedScheduling: insufficient cpu/memory, node taints, unbound PVC, affinity. Check `get_nodes` for pressure and capacity.

## Remediation
- Insufficient capacity -> ESCALATE (cluster autoscaler/node group change). Do NOT scale up the deployment, it worsens the problem.
- Replica count above need -> `scale_deployment` down.
- PVC/affinity/taints -> ESCALATE.
