"""Hybrid RAG: local runbook index (Titan embeddings) + optional managed Bedrock Knowledge Base."""
from __future__ import annotations
import glob
import json
import os
import re
import time
from dataclasses import dataclass

import numpy as np

from .config import Config


@dataclass
class Chunk:
    text: str
    source: str
    score: float


def _chunk(text: str, limit: int = 1500) -> list[str]:
    parts = re.split(r"\n(?=## )", text)
    out: list[str] = []
    for p in parts:
        while len(p) > limit:
            cut = p.rfind("\n", 0, limit) or limit
            out.append(p[:cut]); p = p[cut:]
        if p.strip():
            out.append(p)
    return out


class LocalKB:
    def __init__(self, cfg: Config, llm):
        self.cfg, self.llm = cfg, llm
        self.items: list[dict] = []

    def build(self) -> int:
        items = []
        for path in glob.glob(os.path.join(self.cfg.runbook_dir, "**", "*.md"), recursive=True):
            with open(path) as f:
                for c in _chunk(f.read()):
                    items.append({"source": os.path.relpath(path), "text": c, "vec": self.llm.embed(c)})
        os.makedirs(os.path.dirname(self.cfg.index_path) or ".", exist_ok=True)
        with open(self.cfg.index_path, "w") as f:
            json.dump(items, f)
        self.items = items
        return len(items)

    def _load(self) -> None:
        if self.items:
            return
        if not os.path.exists(self.cfg.index_path):
            self.build()
        else:
            with open(self.cfg.index_path) as f:
                self.items = json.load(f)

    def search(self, query: str, k: int = 4) -> list[Chunk]:
        self._load()
        if not self.items:
            return []
        q = np.array(self.llm.embed(query))
        m = np.array([i["vec"] for i in self.items])
        scores = m @ q  # embeddings are normalized
        return [Chunk(self.items[i]["text"], self.items[i]["source"], float(scores[i]))
                for i in np.argsort(-scores)[:k]]

    def remember(self, title: str, body: str) -> str:
        """Persist a human-approved, successful resolution as a new runbook (feedback loop)."""
        d = os.path.join(self.cfg.runbook_dir, "learned")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{int(time.time())}-{re.sub(r'[^a-z0-9]+', '-', title.lower())[:40]}.md")
        with open(path, "w") as f:
            f.write(f"# {title}\n\n{body}\n")
        return path


class BedrockKB:
    def __init__(self, cfg: Config):
        import boto3
        self.cfg = cfg
        self.rt = boto3.client("bedrock-agent-runtime", region_name=cfg.region)

    def search(self, query: str, k: int = 4) -> list[Chunk]:
        r = self.rt.retrieve(
            knowledgeBaseId=self.cfg.kb_id,
            retrievalQuery={"text": query[:1000]},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": k}},
        )
        out = []
        for x in r.get("retrievalResults", []):
            loc = x.get("location", {})
            src = (loc.get("s3Location") or {}).get("uri") or loc.get("type", "bedrock-kb")
            out.append(Chunk(x["content"]["text"], src, float(x.get("score", 0))))
        return out


class Retriever:
    def __init__(self, cfg: Config, llm):
        self.local = LocalKB(cfg, llm)
        self.managed = BedrockKB(cfg) if cfg.kb_id else None

    def search(self, query: str, k: int = 4) -> list[Chunk]:
        res = self.local.search(query, k)
        if self.managed:
            res += self.managed.search(query, k)
        return sorted(res, key=lambda c: -c.score)[:k + 2]

    @staticmethod
    def format(chunks: list[Chunk]) -> str:
        return "\n\n".join(f"<kb source=\"{c.source}\" score=\"{c.score:.2f}\">\n{c.text}\n</kb>" for c in chunks)
