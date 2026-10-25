#!/usr/bin/env python3
"""A local OpenAI-compatible endpoint in front of Amazon Bedrock.

The harness speaks the OpenAI wire format; Bedrock does not. This shim sits between
them so measuring a Bedrock deployment is two commands instead of an afternoon of
plumbing. It also carries the guardrail configuration, which is the point: you run
the same suite twice, once without a guardrail and once with one, and compare.

    pip install boto3
    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
    python examples/bedrock_adapter.py --model anthropic.claude-3-5-sonnet-20241022-v2:0 --port 8790

    # no guardrail
    python -m rt run --suite suites/owasp_llm01.jsonl --endpoint http://127.0.0.1:8790 \
        --model bedrock --report before.md

    # same, with the guardrail attached
    python examples/bedrock_adapter.py --model <id> --port 8791 --guardrail-id <id> --guardrail-version 1
    python -m rt run --suite suites/owasp_llm01.jsonl --endpoint http://127.0.0.1:8791 \
        --model bedrock --report after.md

The translation functions are pure and tested; the network call is not exercised in
CI, because a test that needs an AWS account is not a test.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_MAX_TOKENS = 512


def to_bedrock_body(payload, model, max_tokens=DEFAULT_MAX_TOKENS):
    """OpenAI chat request -> Anthropic-on-Bedrock request body."""
    messages = []
    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = "assistant" if message.get("role") == "assistant" else "user"
        content = message.get("content")
        if isinstance(content, list):
            content = " ".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
        messages.append({"role": role, "content": str(content or "")})
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": int(payload.get("max_tokens") or max_tokens),
        "temperature": float(payload.get("temperature") or 0.0),
        "messages": messages or [{"role": "user", "content": ""}],
    }
    return body


def to_openai_response(bedrock_payload, model="bedrock", usage=None):
    """Anthropic-on-Bedrock response -> OpenAI chat completion shape."""
    text = ""
    if isinstance(bedrock_payload, dict):
        blocks = bedrock_payload.get("content") or []
        text = "".join(str(block.get("text", "")) for block in blocks if isinstance(block, dict))
        usage = usage or bedrock_payload.get("usage")
    return {
        "id": "bedrock-adapter",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": text}}],
        "usage": usage or {},
    }


def guardrail_config(guardrail_id, version):
    """The Bedrock guardrail block, or None when no guardrail is configured."""
    if not guardrail_id:
        return None
    return {"guardrailIdentifier": guardrail_id, "guardrailVersion": str(version or "DRAFT")}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("bedrock-adapter: " + (fmt % args) + "\n")

    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            self._json(200, {"status": "ok", "model": self.server.model,
                             "guardrail": bool(self.server.guardrail)})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/v1/chat/completions"):
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "body is not JSON"})
            return

        try:
            import boto3  # imported here so the module loads without it
        except ImportError:
            self._json(500, {"error": "boto3 is not installed: pip install boto3"})
            return

        client = boto3.client("bedrock-runtime", region_name=self.server.region)
        request = {
            "modelId": self.server.model,
            "body": json.dumps(to_bedrock_body(payload, self.server.model)),
            "accept": "application/json",
            "contentType": "application/json",
        }
        config = guardrail_config(self.server.guardrail[0] if self.server.guardrail else None,
                                  self.server.guardrail[1] if self.server.guardrail else None)
        if config:
            request["guardrailIdentifier"] = config["guardrailIdentifier"]
            request["guardrailVersion"] = config["guardrailVersion"]
        try:
            response = client.invoke_model(**request)
            body = json.loads(response["body"].read().decode("utf-8"))
        except Exception as error:
            self._json(502, {"error": "bedrock invoke failed: %s" % error})
            return
        self._json(200, to_openai_response(body, model=self.server.model))


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenAI-compatible shim over Amazon Bedrock.")
    parser.add_argument("--model", required=True, help="Bedrock model id")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--guardrail-id")
    parser.add_argument("--guardrail-version", default="DRAFT")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.model = args.model
    server.region = args.region
    server.guardrail = (args.guardrail_id, args.guardrail_version) if args.guardrail_id else None
    print("bedrock adapter on http://127.0.0.1:%d model=%s guardrail=%s" % (
        server.server_address[1], args.model, args.guardrail_id or "none"), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
