"""Secret scrubbing applied to everything that leaves the cluster toward the LLM, logs or audit."""
import re

_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)((?:aws_secret_access_key|secret|password|passwd|pwd|token|api[_-]?key|authorization)[\"']?\s*[=:]\s*)[\"']?[^\s\"',;]+"), r"\1[REDACTED]"),
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\1[REDACTED]\2"),
]


def redact(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
