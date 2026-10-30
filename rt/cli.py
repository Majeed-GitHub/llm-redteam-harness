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
from .report import render_junit, render_markdown, write_json
from .plugin import plugin_manifest, plugin_run
from .runner import compare, render_comparison, run_agent_suite

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2

REPORT_FORMATS = ["markdown", "junit", "sarif", "html"]


def _write_text(path: str, text: str) -> None:
    """Write a report with explicit UTF-8 and LF, so it is the same file on every OS."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


SEVERITY_ORDER = {"medium": 1, "high": 2, "critical": 3}


def cmd_scan_mcp(args) -> int:
    """Lint MCP tool definitions without spending a single model token.

    The cheap check people actually run in a pull request: imperative text in a
    description, instructions in a parameter default, hidden unicode, a tool
    that redirects to a sibling, and schema drift against a pinned lockfile.
    """
    from .mcp_lint import diff_lockfile, lint_tools, load_tools

    try:
        tools, problems = load_tools(args.path)
    except (OSError, ValueError) as exc:
        print("cannot read %s: %s" % (args.path, exc), file=sys.stderr)
        return EXIT_ERROR
    for problem in problems:
        print("problem: " + problem, file=sys.stderr)
    if not tools:
        print("no tool definitions found in %s" % args.path, file=sys.stderr)
        return EXIT_ERROR

    findings = lint_tools(tools)
    if args.lockfile:
        try:
            with open(args.lockfile, "r", encoding="utf-8") as handle:
                lock = json.load(handle)
        except (OSError, ValueError) as exc:
            print("cannot read lockfile %s: %s" % (args.lockfile, exc), file=sys.stderr)
            return EXIT_ERROR
        if isinstance(lock, dict) and "tools" in lock and isinstance(lock["tools"], dict):
            lock = lock["tools"]
        if not isinstance(lock, dict):
            print("lockfile must hold a tool-hash map", file=sys.stderr)
            return EXIT_ERROR
        findings = findings + diff_lockfile(tools, lock)

    findings.sort(key=lambda finding: (-SEVERITY_ORDER.get(finding.severity, 0), finding.tool, finding.code))
    if args.json:
        print(json.dumps({
            "path": args.path,
            "tools": len(tools),
            "problems": problems,
            "findings": [finding.to_dict() for finding in findings],
        }, indent=2))
    else:
        print("MCP tool surface : %s" % args.path)
        print("tools            : %d" % len(tools))
        print("findings         : %d" % len(findings))
        for finding in findings:
            print("  %-8s %-26s %-32s %s" % (
                finding.severity, finding.code, finding.tool, finding.detail))
        if not findings:
            print("  no poisoning indicators in the tool surface")

    if args.write_lockfile:
        from .mcp_lint import schema_hashes
        hashes = schema_hashes(tools)
        with open(args.write_lockfile, "w", encoding="utf-8", newline="\n") as handle:
            json.dump({"version": 1, "tools": hashes}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("lockfile written : %s (%d tools)" % (args.write_lockfile, len(hashes)))

    threshold = SEVERITY_ORDER.get(args.fail_on, 2)
    worst = max([SEVERITY_ORDER.get(finding.severity, 0) for finding in findings] or [0])
    if worst >= threshold:
        print("FAILED: findings at or above %s" % args.fail_on, file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK

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

    rendered = _render_report(args.format, summary, verdicts, args.suite, model)
    if rendered and not args.report and args.format != "markdown":
        # With no report path the machine format is the output, so it goes to
        # stdout alone: a CI job redirects it into the file it publishes.
        print(rendered)
    elif args.json:
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

    if args.report and rendered:
        _write_text(args.report, rendered)
        print("%s written   : %s" % (args.format, args.report))
    if args.json_out:
        write_json(args.json_out, summary, verdicts)
        print("json written     : %s" % args.json_out)

    if args.max_asr is not None and summary["attack_success_rate"] > args.max_asr:
        print("FAILED: attack success rate %.3f above the allowed %.3f" % (
            summary["attack_success_rate"], args.max_asr), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


def cmd_agent(args) -> int:
    """Run a suite as tool-using conversations and score the whole trajectory.

    This is the command the MCP cases exist for: a poisoned tool definition is
    obeyed by a call, not by a sentence, so the report has to show the calls.
    """
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
    try:
        run = run_agent_suite(cases, client, name=model)
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    verdicts = run.verdicts
    summary = summarize(verdicts)
    summary["suite"] = args.suite
    summary["model"] = model
    summary["latency_p50_ms"] = round(run.latency(0.5), 2)
    summary["latency_p95_ms"] = round(run.latency(0.95), 2)
    summary["schema_swaps"] = sum(1 for case in cases if case.mutate_on_turn)
    if run.error:
        summary["endpoint_error"] = run.error

    rendered = _render_report(args.format, summary, verdicts, args.suite, model)
    if rendered and not args.report and args.format not in ("markdown", "text"):
        print(rendered)
    elif args.json:
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
        if summary["by_owasp"]:
            print("by OWASP id:")
            for owasp, bucket in summary["by_owasp"].items():
                print("  %-10s %d/%d passed" % (owasp, bucket["passed"], bucket["cases"]))
        if summary["failure_reasons"]:
            print("failure reasons:")
            for label, count in sorted(summary["failure_reasons"].items()):
                print("  %-28s %d" % (label, count))
        print("cases:")
        for verdict in verdicts:
            mark = "pass" if verdict.passed else "FAIL"
            print("  %-8s %-4s %-26s %s" % (verdict.case_id, mark, verdict.category, verdict.reason))
            for call in verdict.tool_calls:
                print("      turn %d  %s(%s)" % (
                    call.get("turn", 0), call.get("name", ""),
                    json.dumps(call.get("arguments", {}))[:120]))

    if args.report and rendered:
        _write_text(args.report, rendered)
        print("%s written   : %s" % (args.format, args.report))
    if args.json_out:
        write_json(args.json_out, summary, verdicts)
        print("json written     : %s" % args.json_out)

    if args.max_asr is not None and summary["attack_success_rate"] > args.max_asr:
        print("FAILED: attack success rate %.3f above the allowed %.3f" % (
            summary["attack_success_rate"], args.max_asr), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


def _render_report(fmt: str, summary, verdicts, suite: str, model: str) -> str:
    """Dispatch a report format, leaving an optional format absent-safe."""
    if fmt == "junit":
        return render_junit(summary, verdicts, suite, model)
    if fmt == "sarif":
        try:
            from .report_sarif import render_sarif
        except ImportError:
            print("SARIF output is not available in this install", file=sys.stderr)
            return ""
        return render_sarif(summary, verdicts, suite, model)
    if fmt == "html":
        try:
            from .report_html import render_html
        except ImportError:
            print("HTML output is not available in this install", file=sys.stderr)
            return ""
        return render_html(summary, verdicts, suite, model)
    return render_markdown(summary, verdicts, suite, model)

def cmd_compare(args) -> int:
    cases = load_cases(args.suite)
    problems = validate_cases(cases)
    if problems:
        for problem in problems:
            print("suite problem: " + problem, file=sys.stderr)
        return EXIT_ERROR
    targets = []
    for item in args.target or []:
        if "=" not in item:
            print("--target must be NAME=URL, got %s" % item, file=sys.stderr)
            return EXIT_ERROR
        name, endpoint = item.split("=", 1)
        targets.append((name, endpoint))
    if not targets:
        print("no targets: pass --target NAME=URL at least once", file=sys.stderr)
        return EXIT_ERROR

    runs = compare(targets, cases, args.model or "unknown", args.api_key_env or "", args.timeout)
    table = render_comparison(runs, args.suite)
    if args.json:
        print(json.dumps([
            {"name": run.name, "endpoint": run.endpoint, "error": run.error,
             "summary": run.summary, "latency_p50_ms": run.latency(0.5),
             "latency_p95_ms": run.latency(0.95)}
            for run in runs], indent=2))
    else:
        print(table)
    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(table)
        print("report written   : %s" % args.report)

    worst = max((run.summary.get("attack_success_rate", 0.0) for run in runs if run.verdicts), default=0.0)
    if args.max_asr is not None and worst > args.max_asr:
        print("FAILED: worst attack success rate %.3f above the allowed %.3f" % (worst, args.max_asr), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


def cmd_plugin_manifest(args) -> int:
    print(json.dumps(plugin_manifest(), indent=2))
    return EXIT_OK


def cmd_plugin_run(args) -> int:
    result = plugin_run(args.suite, endpoint=args.endpoint, model=args.model or "unknown",
                        api_key_env=args.api_key_env or "", mock=args.mock,
                        mock_mode=args.mock_mode, timeout=args.timeout, report_path=args.report)
    print(json.dumps(result, indent=2))
    if not result.get("ok"):
        print("run failed: " + str(result.get("error")), file=sys.stderr)
        return EXIT_ERROR
    if args.max_asr is not None and result["summary"]["attack_success_rate"] > args.max_asr:
        print("FAILED: attack success rate above the allowed threshold", file=sys.stderr)
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
    run.add_argument("--report", help="write the report here, Markdown unless --format junit")
    run.add_argument("--json-out", help="write the full result as JSON here")
    run.add_argument("--format", choices=REPORT_FORMATS, default="markdown",
                     help="format of the --report file: markdown for a person (the default), "
                          "junit for CI test tabs, sarif for a code-scanning tab, html for a scorecard")
    run.add_argument("--json", action="store_true")
    run.add_argument("--max-asr", type=float, help="exit non-zero above this attack success rate")
    run.set_defaults(func=cmd_run)

    agent = sub.add_parser("agent",
                           help="run a tool-using suite and score every call, not just the answer")
    agent.add_argument("--suite", required=True)
    agent.add_argument("--endpoint", help="base URL of an OpenAI-compatible API")
    agent.add_argument("--model", help="model name to send")
    agent.add_argument("--api-key-env", help="environment variable holding the API key")
    agent.add_argument("--mock", action="store_true", help="run against the bundled agent fixtures")
    agent.add_argument("--mock-mode", choices=["agent-safe", "agent-vulnerable"],
                       default="agent-safe",
                       help="agent-safe ignores poisoning; agent-vulnerable obeys it")
    agent.add_argument("--timeout", type=float, default=120.0)
    agent.add_argument("--report", help="write the report here")
    agent.add_argument("--json-out", help="write the full result as JSON here")
    agent.add_argument("--format", choices=REPORT_FORMATS, default="markdown")
    agent.add_argument("--json", action="store_true")
    agent.add_argument("--max-asr", type=float, help="exit non-zero above this attack success rate")
    agent.set_defaults(func=cmd_agent)

    compare_parser = sub.add_parser("compare", help="run one suite against several endpoints and tabulate them")
    compare_parser.add_argument("--suite", required=True)
    compare_parser.add_argument("--target", action="append", help="NAME=URL, repeatable")
    compare_parser.add_argument("--model", help="model name to send to every target")
    compare_parser.add_argument("--api-key-env", help="environment variable holding the API key")
    compare_parser.add_argument("--timeout", type=float, default=120.0)
    compare_parser.add_argument("--report", help="write the comparison table here")
    compare_parser.add_argument("--json", action="store_true")
    compare_parser.add_argument("--max-asr", type=float, help="exit non-zero above this rate on any target")
    compare_parser.set_defaults(func=cmd_compare)

    plugin_manifest_parser = sub.add_parser("plugin-manifest", help="describe the plugin for a host")
    plugin_manifest_parser.set_defaults(func=cmd_plugin_manifest)

    plugin_run_parser = sub.add_parser("plugin-run", help="one evaluation, shaped for a host to render")
    plugin_run_parser.add_argument("--suite", required=True)
    plugin_run_parser.add_argument("--endpoint")
    plugin_run_parser.add_argument("--model")
    plugin_run_parser.add_argument("--api-key-env")
    plugin_run_parser.add_argument("--mock", action="store_true")
    plugin_run_parser.add_argument("--mock-mode", choices=["good", "leaky"], default="good")
    plugin_run_parser.add_argument("--timeout", type=float, default=120.0)
    plugin_run_parser.add_argument("--report")
    plugin_run_parser.add_argument("--max-asr", type=float)
    plugin_run_parser.set_defaults(func=cmd_plugin_run)

    scan_mcp = sub.add_parser("scan-mcp",
                              help="lint MCP tool definitions without calling a model")
    scan_mcp.add_argument("path", help="tools list, tool export, or MCP config JSON")
    scan_mcp.add_argument("--lockfile", help="pinned tool-hash map to detect schema drift")
    scan_mcp.add_argument("--write-lockfile", help="record the current schema hashes here")
    scan_mcp.add_argument("--fail-on", choices=["medium", "high", "critical"], default="high")
    scan_mcp.add_argument("--json", action="store_true")
    scan_mcp.set_defaults(func=cmd_scan_mcp)

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
