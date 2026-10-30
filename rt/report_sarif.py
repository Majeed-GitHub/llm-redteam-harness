"""SARIF 2.1.0 output: one finding per failed case, for a code-scanning tab.

A JSON report is a file someone has to open; SARIF is a file a host already knows
how to open. GitHub code scanning, VS Code and most CI dashboards render a SARIF
result as a row with a rule, a level and a message, which is exactly the shape a
failed case already has: the rule is the OWASP id when the suite mapped one, and
the judge's reason is already a sentence a reviewer can act on.

A failure on a control case is a warning, not an error: over-refusal is a
usability regression, while a leaked canary or an emitted tool call is the thing
the suite exists to catch. The distinction comes from the expectation, not from
the category, because a suite can map both kinds of case to the same OWASP id.

The output is deterministic on purpose. Findings follow verdict order, no
timestamp, hostname or absolute path is embedded, and the JSON is written with a
fixed layout, so two runs of the same input are byte-identical and a diff only
shows real change.

Results carry no physical location: the finding is about a model's answer, not a
line of source, and pointing a scanner at a file it never read would be a lie.
"""

from __future__ import annotations

import json
from typing import Dict, Sequence

import rt

from .judges import Verdict, is_control

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "llm-redteam"
INFORMATION_URI = "https://github.com/Majeed-GitHub/llm-redteam-harness"


def _level(verdict: Verdict) -> str:
    """A failed control is over-refusal; a failed attack case is a security defect.

    The decision is shared with the scorer through judges.is_control, so a
    poisoning case that carries "comply" is never filed as a warning.
    """
    return "warning" if is_control(verdict) else "error"


def _result(verdict: Verdict) -> Dict[str, object]:
    owasp = getattr(verdict, "owasp", "") or ""
    return {
        "ruleId": str(owasp or verdict.category),
        "level": _level(verdict),
        "message": {"text": str(verdict.reason)},
        "properties": {
            "category": str(verdict.category),
            "owasp": str(owasp),
            "expectation": str(verdict.expectation),
            "case_id": str(verdict.case_id),
        },
    }


def render_sarif(summary: Dict[str, object], verdicts: Sequence[Verdict],
                 suite: str = "", model: str = "") -> str:
    """Render one SARIF run whose results are exactly the failed verdicts.

    summary is accepted so the same pair can be handed to every renderer, but the
    results are derived from the verdicts themselves: the file has to describe
    exactly the findings it contains, not a count taken from somewhere else.

    __version__ is read from the package at render time rather than imported by
    value, so the driver version always matches the code that produced the run.
    """
    results = [_result(verdict) for verdict in verdicts if not verdict.passed]
    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": INFORMATION_URI,
                    "version": str(getattr(rt, "__version__", "0")),
                },
            },
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "properties": {"suite": suite or "", "model": model or ""},
        }],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
