"""Thin wrapper over Bedrock Runtime: Converse API (tool use) + Titan embeddings."""
from __future__ import annotations
import json

import boto3
from botocore.config import Config as BotoConfig

from .config import Config


class Bedrock:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rt = boto3.client(
            "bedrock-runtime", region_name=cfg.region,
            config=BotoConfig(retries={"max_attempts": 5, "mode": "adaptive"}, read_timeout=120),
        )

    def converse(self, system: str, messages: list[dict], tools: dict | None = None,
                 max_tokens: int = 2048) -> dict:
        kwargs = dict(
            modelId=self.cfg.model_id,
            system=[{"text": system}],
            messages=messages,
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.0},
        )
        if tools:
            kwargs["toolConfig"] = tools
        if self.cfg.guardrail_id:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self.cfg.guardrail_id,
                "guardrailVersion": self.cfg.guardrail_version,
            }
        return self.rt.converse(**kwargs)

    def structured(self, system: str, prompt: str, name: str, description: str, schema: dict) -> dict:
        """Force the model to return JSON matching `schema` via a forced tool call."""
        tools = {
            "tools": [{"toolSpec": {"name": name, "description": description, "inputSchema": {"json": schema}}}],
            "toolChoice": {"tool": {"name": name}},
        }
        resp = self.converse(system, [{"role": "user", "content": [{"text": prompt}]}], tools, max_tokens=3000)
        for block in resp["output"]["message"]["content"]:
            if "toolUse" in block:
                return block["toolUse"]["input"]
        raise RuntimeError("model did not return structured output")

    def embed(self, text: str) -> list[float]:
        body = json.dumps({"inputText": text[:8000], "dimensions": 512, "normalize": True})
        r = self.rt.invoke_model(modelId=self.cfg.embed_model_id, body=body)
        return json.loads(r["body"].read())["embedding"]
