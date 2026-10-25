"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .cases import load_cases, summarise_cases, validate_cases
from .client import ChatClient, ClientError
from .judges import judge, summarize
from .mock import serve
from .report import render_markdown, write_json

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2


def cmd_validate(args) -> int:
    cases = load_cases(args.suite)
    problems = validate_cases(cases)
    print(summarise_cases(cases))
    if problems:
        print("\nproblems:")
        for problem in problems:
            print("  " + problem)
        return EXIT_FAILED
    print("suite is valid")
    return EXIT_OK


def cmd_run(args) -> int:
    cases = load_cases(args.suite)
    problems = validate_cases(cases)
    if problems:
        for problem in problems:
            print("suite problem: " + problem, file=sys.stderr)
        return EXIT_ERROR

    server = None
    endpoint = args.endpoint
    model = args.model or "mock"
    if args.mock:
        server, endpoint = serve(mode=args.mock_mode)
        model = "mock-" + args.mock_mode
    if not endpoint:
        print("no endpoint: pass --endpoint or --mock", file=sys.stderr)
        return EXIT_ERROR

    client = ChatClient(endpoint=endpoint, model=model, api_key_env=args.api_key_env or "",
                        timeout=args.timeout)
    verdicts = []
    try:
        for case in cases:
            try:
                response = client.complete(case.prompt)
            except ClientError as error:
                print("case %s: %s" % (case.id, error), file=sys.stderr)
                return EXIT_ERROR
            verdicts.append(judge(case, response))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    summary = summarize(verdicts)
    summary["suite"] = args.suite
    summary["model"] = model

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("suite            : %s" % args.suite)
        print("model            : %s" % model)
        print("cases            : %d" % summary["cases"])
        print("attacks          : %d" % summary["attacks"])
        print("succeeded        : %d" % summary["attacks_succeeded"])
        print("attack success   : %.1f%%" % (summary["attack_success_rate"] * 100))
        print("robustness       : %.1f%%" % (summary["robustness"] * 100))
        print("over-refusal     : %.1f%%" % (summary["over_refusal_rate"] * 100))
        print("by category:")
        for name, bucket in summary["by_category"].items():
            print("  %-26s %d/%d attacked" % (name, bucket["succeeded"], bucket["attacks"]))
        if summary["failures"]:
            print("failures:")
            for failure in summary["failures"][:12]:
                print("  %-10s %s" % (failure["case_id"], failure["reason"]))

    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_markdown(summary, verdicts, args.suite, model))
        print("report written   : %s" % args.report)
    if args.json_out:
        write_json(args.json_out, summary, verdicts)
        print("json written     : %s" % args.json_out)

    if args.max_asr is not None and summary["attack_success_rate"] > args.max_asr:
        print("FAILED: attack success rate %.3f above the allowed %.3f" % (
            summary["attack_success_rate"], args.max_asr), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rt", description="Reproducible LLM security testing.")
    parser.add_argument("--version", action="version", version="rt " + __version__)
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run a suite against a model")
    run.add_argument("--suite", required=True)
    run.add_argument("--endpoint", help="base URL of an OpenAI-compatible API")
    run.add_argument("--model", help="model name to send")
    run.add_argument("--api-key-env", help="environment variable holding the API key")
    run.add_argument("--mock", action="store_true", help="run against the bundled mock model")
    run.add_argument("--mock-mode", choices=["good", "leaky"], default="good")
    run.add_argument("--timeout", type=float, default=120.0)
    run.add_argument("--report", help="write a Markdown report here")
    run.add_argument("--json-out", help="write the full result as JSON here")
    run.add_argument("--json", action="store_true")
    run.add_argument("--max-asr", type=float, help="exit non-zero above this attack success rate")
    run.set_defaults(func=cmd_run)

    validate = sub.add_parser("validate", help="check a suite before running it")
    validate.add_argument("--suite", required=True)
    validate.set_defaults(func=cmd_validate)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
