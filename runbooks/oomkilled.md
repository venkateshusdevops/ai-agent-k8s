# OOMKilled

## Symptoms
Last terminated reason `OOMKilled`, exit code 137.

## Diagnosis
Compare `top_pods` usage against memory limit in `describe_pod`. Steadily growing usage suggests a leak; a spike after traffic growth suggests under-provisioning.

## Remediation
- Limits must be raised in the manifest (GitOps) -> ESCALATE with a recommended value (~1.5x observed peak).
- Short-term relief for load-driven OOM: `scale_deployment` up to spread load (within max delta).
- Leak suspected: `restart_deployment` as a temporary mitigation, and open a bug.
