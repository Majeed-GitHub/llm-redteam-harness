"""Reports: JSON for tooling, Markdown for a human, JUnit XML for CI."""

from __future__ import annotations

import json
from typing import Dict, Sequence
from xml.sax.saxutils import escape, quoteattr

from .judges import Verdict


def write_json(path: str, summary: Dict[str, object], verdicts: Sequence[Verdict]) -> None:
    payload = dict(summary)
    payload["verdicts"] = [verdict.to_dict() for verdict in verdicts]
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)


def render_markdown(summary: Dict[str, object], verdicts: Sequence[Verdict],
                    suite: str = "", model: str = "") -> str:
    lines = [
        "# LLM security test report",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| suite | %s |" % (suite or "-"),
        "| model | %s |" % (model or "mock"),
        "| cases | %d |" % summary["cases"],
        "| attacks | %d |" % summary["attacks"],
        "| attack success rate | %.1f%% |" % (summary["attack_success_rate"] * 100),
        "| robustness | %.1f%% |" % (summary["robustness"] * 100),
        "| over-refusal on controls | %.1f%% |" % (summary["over_refusal_rate"] * 100),
        "",
        "## By category",
        "",
        "| Category | Attacks | Succeeded | ASR |",
        "| --- | --- | --- | --- |",
    ]
    for name, bucket in summary["by_category"].items():
        lines.append("| %s | %d | %d | %.1f%% |" % (
            name, bucket["attacks"], bucket["succeeded"], bucket["asr"] * 100))
    lines += ["", "## Cases", "", "| Case | Category | Expectation | Result | Reason |",
              "| --- | --- | --- | --- | --- |"]
    for verdict in verdicts:
        lines.append("| %s | %s | %s | %s | %s |" % (
            verdict.case_id, verdict.category, verdict.expectation,
            "pass" if verdict.passed else "FAIL", verdict.reason))
    if summary["failures"]:
        lines += ["", "## Failures", ""]
        for failure in summary["failures"]:
            lines.append("- %s (%s): %s" % (failure["case_id"], failure["category"], failure["reason"]))
    lines += ["", "Reproduce this table with the exact command in the README; the suite is fixed,",
              "the temperature is 0, and the judges are rules in rt/judges.py.", ""]
    return "\n".join(lines)


def render_junit(summary: Dict[str, object], verdicts: Sequence[Verdict],
                 suite: str = "", model: str = "") -> str:
    """JUnit XML, so a CI job can show one row per case instead of one number.

    A CI host already knows how to render this format: a case that failed is a
    red row with the judge's reason attached, which is what makes a run
    actionable in a pull request rather than a number buried in a log. The
    counts come from the verdicts themselves rather than from summary, because
    they have to describe exactly the testcases emitted below; summary is
    accepted so callers can hand the same pair to render_markdown and to this.

    Values go through quoteattr and escape instead of hand-written quotes: the
    judge reasons contain quotes and angle brackets by construction, and one
    unescaped "<" would turn the whole document into something no CI can parse.
    """
    failed = [verdict for verdict in verdicts if not verdict.passed]
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<testsuites>",
        '  <testsuite name=%s tests="%d" failures="%d" errors="0" skipped="0" time="0">'
        % (quoteattr(suite or "llm-redteam"), len(verdicts), len(failed)),
    ]
    for verdict in verdicts:
        attributes = 'classname=%s name=%s time="0"' % (
            quoteattr(verdict.category), quoteattr(verdict.case_id))
        if verdict.passed:
            lines.append("    <testcase %s />" % attributes)
            continue
        lines.append("    <testcase %s>" % attributes)
        lines.append("      <failure message=%s>%s</failure>" % (
            quoteattr(verdict.reason), escape(verdict.reason)))
        lines.append("    </testcase>")
    lines += ["  </testsuite>", "</testsuites>", ""]
    return "\n".join(lines)
