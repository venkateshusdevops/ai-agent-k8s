"""Append-only JSONL audit log with a hash chain so tampering is detectable."""
from __future__ import annotations
import hashlib
import json
import os
import time

from .redact import redact


class Audit:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64
        last = "0" * 64
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def log(self, event: str, **data) -> None:
        rec = {"ts": time.time(), "event": event,
               "data": json.loads(redact(json.dumps(data, default=str))), "prev": self._prev}
        body = json.dumps(rec, sort_keys=True)
        rec["hash"] = hashlib.sha256(body.encode()).hexdigest()
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self._prev = rec["hash"]


def verify_chain(path: str) -> bool:
    prev = "0" * 64
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
                return False
            prev = h
    return True
