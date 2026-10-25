"""A minimal OpenAI-compatible chat client, stdlib only."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass


class ClientError(RuntimeError):
    pass


@dataclass
class ChatClient:
    endpoint: str
    model: str
    api_key_env: str = ""
    timeout: float = 120.0
    temperature: float = 0.0

    def _key(self) -> str:
        if not self.api_key_env:
            return ""
        return os.environ.get(self.api_key_env, "")

    def complete(self, prompt: str) -> str:
        """One completion. Temperature defaults to 0 so a run is reproducible."""
        body = json.dumps({
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint.rstrip("/") + "/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        key = self._key()
        if key:
            request.add_header("Authorization", "Bearer " + key)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as error:
            raise ClientError("endpoint returned %s: %s" % (error.code, error.read()[:200]))
        except Exception as error:
            raise ClientError("could not reach the endpoint: %s" % error)
        return response_text(payload)


def response_text(payload: object) -> str:
    if isinstance(payload, dict):
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            if isinstance(message, dict) and message.get("content"):
                return str(message["content"])
            return str(choices[0].get("text") or "")
    return ""
