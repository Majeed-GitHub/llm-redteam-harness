"""A single-file dark-mode HTML report: attach it to a ticket and it still works.

The file is meant to be opened from disk, years later, on a laptop with no
network, so it embeds every byte it needs: styles are inline in a <style> block,
there are no fonts, images or scripts, and the case list uses native <details>
elements so it collapses without JavaScript. Nothing about the content depends
on a script running.

Case text is the one thing a report cannot control. A judge reason can contain
angle brackets, a model response can contain a script tag, and tool arguments can
contain quotes, so every value that reaches the page goes through html.escape
first. A reason is shown, never executed.

Pass rates come from the verdicts rather than from summary: each <details> must
correspond to exactly one case in the table above it, and an empty run has to
render as an empty page instead of raising.
"""

from __future__ import annotations

import html
import json
from typing import Callable, Dict, List, Sequence, Tuple

from .judges import Verdict

STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #0d1117;
  color: #e6edf3;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 72rem; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
header { border-bottom: 1px solid #30363d; padding-bottom: 1.5rem; margin-bottom: 1.5rem; }
.eyebrow {
  margin: 0 0 .35rem;
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: .72rem;
  color: #8b949e;
}
h1 { margin: 0 0 1.1rem; font-size: 1.9rem; letter-spacing: -.02em; }
h2 { font-size: 1.12rem; margin: 2.1rem 0 .7rem; }
.meta {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: .35rem 1.25rem;
  margin: 0 0 1.25rem;
}
.meta dt { color: #8b949e; }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.score { margin: 0; }
.score strong { font-size: 2rem; color: #58a6ff; }
.muted { color: #8b949e; }
table {
  width: 100%;
  border-collapse: collapse;
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: .5rem;
  overflow: hidden;
}
th, td {
  text-align: left;
  padding: .55rem .8rem;
  border-bottom: 1px solid #21262d;
  vertical-align: top;
}
th {
  font-size: .76rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #8b949e;
  font-weight: 600;
}
tbody tr:last-child td { border-bottom: 0; }
td.rate-cell { font-variant-numeric: tabular-nums; }
details.case {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: .5rem;
  margin: .6rem 0;
}
details.case > summary {
  cursor: pointer;
  padding: .7rem .9rem;
  list-style-position: inside;
}
details.case[open] > summary { border-bottom: 1px solid #21262d; }
.badge {
  margin-right: .45rem;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .08em;
  padding: .1rem .4rem;
  border-radius: .3rem;
}
.badge.pass {
  color: #3fb950;
  background: rgba(63, 185, 80, .12);
  border: 1px solid rgba(63, 185, 80, .4);
}
.badge.fail {
  color: #f85149;
  background: rgba(248, 81, 73, .12);
  border: 1px solid rgba(248, 81, 73, .4);
}
.case-id {
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
  font-weight: 600;
}
.body { padding: .25rem 1rem 1rem; }
.body dl {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: .45rem 1.25rem;
  margin: .8rem 0 0;
}
.body dt { color: #8b949e; }
.body dd { margin: 0; min-width: 0; }
pre {
  margin: 0;
  padding: .6rem .75rem;
  background: #0d1117;
  border: 1px solid #21262d;
  border-radius: .35rem;
  overflow-x: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: .85rem/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
}
table.calls { margin: .1rem 0 0; }
table.calls th, table.calls td { padding: .45rem .6rem; }
"""


def _escape(value: object) -> str:
    """One funnel for every value that reaches the page."""
    return html.escape("" if value is None else str(value), quote=True)


def _rate(passed: int, total: int) -> str:
    if not total:
        return "n/a"
    return "%.1f%%" % (100.0 * passed / total)


def _milliseconds(value: object) -> str:
    try:
        return "%.1f ms" % float(value)
    except (TypeError, ValueError):
        return _escape(value)


def _category(verdict: Verdict) -> str:
    return str(verdict.category)


def _owasp(verdict: Verdict) -> str:
    return str(getattr(verdict, "owasp", "") or "unmapped")


def _groups(verdicts: Sequence[Verdict],
            key: Callable[[Verdict], str]) -> List[Tuple[str, int, int]]:
    buckets: Dict[str, List[int]] = {}
    for verdict in verdicts:
        bucket = buckets.setdefault(key(verdict), [0, 0])
        bucket[0] += 1 if verdict.passed else 0
        bucket[1] += 1
    return [(name, buckets[name][0], buckets[name][1]) for name in sorted(buckets)]


def _rate_table(heading: str, column: str,
                rows: Sequence[Tuple[str, int, int]]) -> List[str]:
    lines = [
        "<section>",
        "<h2>%s</h2>" % _escape(heading),
        '<table class="rates">',
        "<thead><tr><th>%s</th><th>Passed</th><th>Cases</th><th>Pass rate</th></tr></thead>"
        % _escape(column),
        "<tbody>",
    ]
    if rows:
        for name, passed, total in rows:
            lines.append(
                '<tr><td>%s</td><td>%d</td><td>%d</td><td class="rate-cell">%s</td></tr>'
                % (_escape(name), passed, total, _rate(passed, total)))
    else:
        lines.append('<tr><td colspan="4" class="muted">no cases</td></tr>')
    lines += ["</tbody>", "</table>", "</section>"]
    return lines


def _arguments(value: object) -> str:
    """Tool arguments arrive as whatever the target emitted; show JSON when it is JSON."""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)
    return "" if value is None else str(value)


def _tool_calls(verdict: Verdict) -> List[str]:
    calls = list(getattr(verdict, "tool_calls", None) or [])
    if not calls:
        return ['<p class="muted">no tool calls</p>']
    lines = [
        '<table class="calls">',
        "<thead><tr><th>#</th><th>Tool</th><th>Arguments</th></tr></thead>",
        "<tbody>",
    ]
    for index, call in enumerate(calls, 1):
        if isinstance(call, dict):
            name = call.get("name", "")
            arguments = call.get("arguments", "")
        else:
            name, arguments = "", call
        lines.append("<tr><td>%d</td><td>%s</td><td><pre>%s</pre></td></tr>" % (
            index, _escape(name), _escape(_arguments(arguments))))
    lines += ["</tbody>", "</table>"]
    return lines


def _final_text(verdict: Verdict) -> str:
    response = verdict.response or ""
    if not response:
        return '<span class="muted">(empty)</span>'
    return "<pre>%s</pre>" % _escape(response)


def _case(verdict: Verdict) -> List[str]:
    state = "pass" if verdict.passed else "fail"
    lines = [
        '<details class="case %s">' % state,
        '<summary><span class="badge %s">%s</span><span class="case-id">%s</span>'
        ' <span class="muted">%s / %s</span></summary>' % (
            state, "PASS" if verdict.passed else "FAIL", _escape(verdict.case_id),
            _escape(verdict.category), _escape(verdict.expectation)),
        '<div class="body">',
        "<dl>",
        "<dt>Case</dt><dd>%s</dd>" % _escape(verdict.case_id),
        "<dt>Category</dt><dd>%s</dd>" % _escape(verdict.category),
        "<dt>OWASP</dt><dd>%s</dd>" % _escape(_owasp(verdict)),
        "<dt>Expectation</dt><dd>%s</dd>" % _escape(verdict.expectation),
        "<dt>Result</dt><dd>%s</dd>" % state,
        "<dt>Reason</dt><dd>%s</dd>" % _escape(verdict.reason),
        "<dt>Final text</dt><dd>%s</dd>" % _final_text(verdict),
        "<dt>Tool calls</dt><dd>",
    ]
    lines += _tool_calls(verdict)
    lines += ["</dd>", "</dl>", "</div>", "</details>"]
    return lines


def render_html(summary: Dict[str, object], verdicts: Sequence[Verdict],
                suite: str = "", model: str = "") -> str:
    """Render one self-contained page: header, two rate tables, one block per case.

    The overall pass rate counts every verdict, controls included, because the
    question the header answers is "how often did the model do what the case
    expected", not "how many attacks got through". The attack success rate lives
    in the JSON and Markdown reports, where it has room for its own caveat.
    """
    summary = summary or {}
    verdicts = list(verdicts)
    passed = sum(1 for verdict in verdicts if verdict.passed)
    total = len(verdicts)
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>LLM red-team report</title>",
        "<style>",
        STYLE,
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        '<p class="eyebrow">llm-redteam</p>',
        "<h1>LLM red-team report</h1>",
        '<dl class="meta">',
        "<dt>Suite</dt><dd>%s</dd>" % _escape(suite or "-"),
        "<dt>Model</dt><dd>%s</dd>" % _escape(model or "mock"),
        "<dt>Cases</dt><dd>%d</dd>" % total,
    ]
    if "latency_p50_ms" in summary or "latency_p95_ms" in summary:
        lines.append("<dt>Latency p50 / p95</dt><dd>%s / %s</dd>" % (
            _milliseconds(summary.get("latency_p50_ms")),
            _milliseconds(summary.get("latency_p95_ms"))))
    lines += [
        "</dl>",
        '<p class="score"><strong>%s</strong> overall pass rate '
        '<span class="muted">(%d of %d cases)</span></p>' % (_rate(passed, total), passed, total),
        "</header>",
    ]
    lines += _rate_table("Pass rate by category", "Category", _groups(verdicts, _category))
    owasp_rows = _groups(verdicts, _owasp)
    owasp_rows.sort(key=lambda row: (row[0] == "unmapped", row[0]))
    lines += _rate_table("Pass rate by OWASP id", "OWASP id", owasp_rows)
    lines += ["<section>", "<h2>Cases</h2>"]
    if verdicts:
        for verdict in verdicts:
            lines += _case(verdict)
    else:
        lines.append('<p class="muted">no cases in this run</p>')
    lines += ["</section>", "</main>", "</body>", "</html>"]
    return "\n".join(lines) + "\n"
