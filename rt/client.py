"""An OpenAI-compatible chat client with native tool calling, stdlib only.

Two call shapes matter for agent testing. The plain completion answers text;
the tool call answers "what does the model want to run next", and that is where
tool poisoning actually lands. Both hit /v1/chat/completions so a real endpoint,
a local model server and the bundled mock are interchangeable.

The parser is deliberately forgiving about argument encoding and strict about
identity: a call with unparseable arguments is still recorded, because a harness
that drops it would report a clean run for an agent that tried to exfiltrate.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


class ClientError(RuntimeError):
    pass


@dataclass
class ToolCall:
    """One tool call as the model emitted it."""

    id: str
    name: str
    arguments_raw: str = "{}"
    arguments: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "arguments_raw": self.arguments_raw,
        }


@dataclass
class AssistantTurn:
    """One model response: either text, or one or more tool calls."""

    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    finish_reason: str = ""

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


def parse_arguments(raw: object) -> tuple:
    """Return (dict, raw string). Bad JSON is kept, not discarded."""
    text = raw if isinstance(raw, str) else json.dumps(raw or {})
    try:
        parsed = json.loads(text) if text.strip() else {}
        if not isinstance(parsed, dict):
            return {"__value__": parsed}, text
        return parsed, text
    except ValueError:
        return {"__unparsed__": text}, text


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

    def _post(self, body: Dict[str, object]) -> Dict[str, object]:
        request = urllib.request.Request(
            self.endpoint.rstrip("/") + "/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
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
        if not isinstance(payload, dict):
            return {}
        return payload

    def complete(self, prompt: str) -> str:
        """One completion. Temperature defaults to 0 so a run is reproducible."""
        payload = self._post({
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        })
        return response_text(payload)

    def complete_with_tools(self, messages: Sequence[Dict[str, object]],
                            tools: Optional[Sequence[Dict[str, object]]] = None) -> AssistantTurn:
        """One agent step: text, tool calls, or both."""
        body: Dict[str, object] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [dict(message) for message in messages],
        }
        if tools:
            body["tools"] = [
                {"type": "function", "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
                }}
                for tool in tools
            ]
            body["tool_choice"] = "auto"
        payload = self._post(body)
        return assistant_turn(payload)


def assistant_turn(payload: object) -> AssistantTurn:
    """Parse a chat completion into content plus tool calls."""
    if not isinstance(payload, dict):
        return AssistantTurn()
    choices = payload.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return AssistantTurn()
    choice = choices[0]
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        return AssistantTurn()
    content = message.get("content") or choice.get("text") or ""
    if isinstance(content, list):
        content = " ".join(str(part.get("text", "")) if isinstance(part, dict) else str(part)
                           for part in content)
    calls: List[ToolCall] = []
    for index, raw_call in enumerate(message.get("tool_calls") or []):
        if not isinstance(raw_call, dict):
            continue
        function = raw_call.get("function") or {}
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        arguments, raw_text = parse_arguments(function.get("arguments"))
        calls.append(ToolCall(
            id=str(raw_call.get("id") or "call-%d" % index),
            name=name,
            arguments_raw=raw_text,
            arguments=arguments,
        ))
    return AssistantTurn(content=str(content or ""), tool_calls=calls,
                         finish_reason=str(choice.get("finish_reason") or ""))


def response_text(payload: object) -> str:
    if isinstance(payload, dict):
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            if isinstance(message, dict) and message.get("content"):
                return str(message["content"])
            return str(choices[0].get("text") or "")
    return ""
