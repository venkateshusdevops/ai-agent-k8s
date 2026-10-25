# CrashLoopBackOff

## Symptoms
Pod state `waiting:CrashLoopBackOff`, rising restart count, exit code != 0.

## Diagnosis
1. `describe_pod`: check last termination reason and exit code (1 = app error, 137 = SIGKILL/OOM, 139 = segfault).
2. `get_logs` with previous=true: look for config errors, missing env, dependency connection failures.
3. `get_rollout_history`: did the crash begin right after a new revision?

## Remediation
- Crash began after a new revision -> `rollback_deployment` (high risk, needs confirmation).
- Transient dependency outage that has recovered -> `restart_deployment`.
- Bad config/secret reference -> ESCALATE, requires manifest change.
