# ImagePullBackOff / ErrImagePull

## Diagnosis
`get_events` shows reason (not found, unauthorized, rate limited). Compare image tag with `get_rollout_history`.

## Remediation
- Tag does not exist or the registry credential is wrong -> `rollback_deployment` if a healthy previous revision exists, otherwise ESCALATE.
- ECR token expiry / transient registry error -> `delete_pod` to retry pull after confirming the registry is reachable.
