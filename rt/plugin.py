"""The embedding contract for a host plugin: an editor panel, a CI job, a desktop app.

A host cannot call Python objects, so it needs a process boundary and a stable JSON
shape. This module is that contract: one manifest describing what the plugin does,
and one result object describing what a run found. Both are versioned, because a
host that parses a shape you changed without saying so is a host that breaks.

Standard library only, like the rest of the package.
"""

from __future__ import annotations

import json
from typing import Dict, Optional

from . import __version__
from .cases import load_cases, validate_cases
from .client import ChatClient, ClientError
from .judges import judge, summarize
from .mock import serve
from .report import render_markdown

SCHEMA = "redlens.redteam-eval/1"
PLUGIN_NAME = "redteam-eval"


def plugin_manifest() -> Dict[str, object]:
    """What a host needs in order to describe this plugin before running it."""
    return {
        "schema": SCHEMA,
        "name": PLUGIN_NAME,
        "version": __version__,
        "title": "Red-team evaluation",
        "description": "Run a graded prompt-injection suite against a model or gateway and "
                       "report the attack success rate. It measures; it does not bypass.",
        "entrypoint": {"command": "python", "args": ["-m", "rt", "plugin-run"]},
        "commands": [
            {"id": "run", "title": "Evaluate this model",
             "required": ["--suite", "PATH"],
             "optional": ["--endpoint", "URL", "--model", "NAME", "--api-key-env", "VAR", "--mock"]},
            {"id": "manifest", "title": "Describe the plugin", "required": []},
        ],
        "permissions": {
            "network": "only to the endpoint passed on the command line; none with --mock",
            "filesystem": "reads the suite it is pointed at; writes only the report path given",
            "secrets": "reads the key from the environment variable named, never from disk",
            "subprocesses": "none",
        },
        "output_schema": SCHEMA,
        "limits": "34-case starting suite, rule judges rather than a model judge, measures a "
                  "model rather than modifying one.",
    }


def plugin_run(suite: str, endpoint: Optional[str] = None, model: str = "unknown",
               api_key_env: str = "", mock: bool = False, mock_mode: str = "good",
               timeout: float = 120.0, report_path: Optional[str] = None) -> Dict[str, object]:
    """One evaluation, shaped so a host can render it without parsing prose."""
    try:
        cases = load_cases(suite)
    except ValueError as error:
        # A host boundary must not raise: a bad path is a result, not a crash.
        return {"schema": SCHEMA, "ok": False, "error": str(error)}
    problems = validate_cases(cases)
    if problems:
        return {"schema": SCHEMA, "ok": False,
                "error": "suite is not valid: " + "; ".join(problems)}

    server = None
    verdicts = []
    try:
        if mock:
            server, endpoint = serve(mode=mock_mode)
            model = "mock-" + mock_mode
        if not endpoint:
            return {"schema": SCHEMA, "ok": False, "error": "no endpoint given and --mock not set"}
        client = ChatClient(endpoint=endpoint, model=model, api_key_env=api_key_env, timeout=timeout)
        for case in cases:
            try:
                verdicts.append(judge(case, client.complete(case.prompt)))
            except ClientError as error:
                return {"schema": SCHEMA, "ok": False, "error": str(error)}
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    summary = summarize(verdicts)
    markdown = render_markdown(summary, verdicts, suite, model)
    if report_path:
        with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown)

    return {
        "schema": SCHEMA,
        "ok": True,
        "suite": suite,
        "model": model,
        "summary": summary,
        "by_category": summary["by_category"],
        "failures": summary["failures"],
        "markdown": markdown,
        "report_path": report_path or "",
    }


def main(argv=None) -> int:
    """Tiny standalone entrypoint so a host can call this file directly."""
    import argparse
    parser = argparse.ArgumentParser(prog="rt-plugin", description="Red-team evaluation plugin contract.")
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument("--suite")
    parser.add_argument("--endpoint")
    parser.add_argument("--model", default="unknown")
    parser.add_argument("--api-key-env", default="")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--mock-mode", choices=["good", "leaky"], default="good")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    if args.manifest or not args.suite:
        print(json.dumps(plugin_manifest(), indent=2))
        return 0
    result = plugin_run(args.suite, endpoint=args.endpoint, model=args.model,
                        api_key_env=args.api_key_env, mock=args.mock, mock_mode=args.mock_mode,
                        timeout=args.timeout, report_path=args.report)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
