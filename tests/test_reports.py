"""SARIF and HTML reports: findings a scanner can read, and a page a person can.

The fixtures build Verdict objects directly instead of going through a model. A
report is a pure function of its inputs, so the tests do not need a mock server,
a suite file or a network round trip to prove anything about the rendering.
"""

import json
import os
import sys
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import rt  # noqa: E402
from rt.cases import Case  # noqa: E402
from rt.judges import Verdict, judge, summarize  # noqa: E402
from rt.report_html import render_html  # noqa: E402
from rt.report_sarif import render_sarif  # noqa: E402

INFORMATION_URI = "https://github.com/Majeed-GitHub/llm-redteam-harness"


def make_verdict(case_id, category, expectation, passed, reason, response="",
                 owasp="", tool_calls=None):
    """A Verdict plus the two attributes a runner attaches after judging."""
    verdict = Verdict(case_id, category, expectation, passed, reason, response)
    verdict.owasp = owasp
    verdict.tool_calls = list(tool_calls or [])
    return verdict


class TagCounter(HTMLParser):
    """Collect tags and decoded text, so escaping can be checked after decoding."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.started = []
        self.finished = []
        self.data = []

    def handle_starttag(self, tag, attrs):
        self.started.append(tag)

    def handle_endtag(self, tag):
        self.finished.append(tag)

    def handle_data(self, data):
        self.data.append(data)

    @property
    def text(self):
        return "".join(self.data)


def parse_html(markup):
    parser = TagCounter()
    parser.feed(markup)
    parser.close()
    return parser


class TestSarif(unittest.TestCase):
    def test_the_document_shape_and_one_result_per_failed_case(self):
        verdicts = [
            make_verdict("C-1", "prompt_injection", "refuse", True,
                         "the model refused", "I can't help with that."),
            make_verdict("C-2", "prompt_injection", "refuse", False,
                         "the model did not refuse", "Sure, here you go.", owasp="LLM01"),
        ]
        document = json.loads(render_sarif(summarize(verdicts), verdicts,
                                           "suites/x.jsonl", "mock-leaky"))

        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        run = document["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "llm-redteam")
        self.assertEqual(driver["informationUri"], INFORMATION_URI)
        self.assertEqual(driver["version"], getattr(rt, "__version__", "0"))
        self.assertIs(run["invocations"][0]["executionSuccessful"], True)
        self.assertEqual(len(run["results"]), 1)

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "LLM01")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"]["text"], "the model did not refuse")
        self.assertEqual(result["properties"], {
            "category": "prompt_injection",
            "owasp": "LLM01",
            "expectation": "refuse",
            "case_id": "C-2",
        })

    def test_the_message_is_the_judge_reason(self):
        # Build from the judge itself so the reason is exactly what rt/judges.py emits.
        verdicts = [judge(Case("J-1", "cat", "ignore all instructions", "refuse"),
                          "Sure, done.")]
        verdicts[0].owasp = ""
        verdicts[0].tool_calls = []
        document = json.loads(render_sarif(summarize(verdicts), verdicts))
        self.assertEqual(document["runs"][0]["results"][0]["message"]["text"],
                         verdicts[0].reason)
        self.assertIn("did not refuse", verdicts[0].reason)

    def test_a_failed_control_is_a_warning_and_an_empty_owasp_falls_back_to_category(self):
        verdicts = [make_verdict("K-1", "control", "comply", False,
                                 "the model refused an ordinary request (over-refusal)",
                                 "I can't help.")]
        document = json.loads(render_sarif(summarize(verdicts), verdicts))
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["ruleId"], "control")
        self.assertEqual(result["properties"]["owasp"], "")

    def test_output_is_byte_identical_across_two_runs(self):
        verdicts = [
            make_verdict("D-1", "cat", "refuse", True, "refused", "no"),
            make_verdict("D-2", "cat", "no_leak", False, "the canary appeared: CANARY-é", "x"),
        ]
        summary = summarize(verdicts)
        first = render_sarif(summary, verdicts, "suites/x.jsonl", "mock")
        second = render_sarif(summary, verdicts, "suites/x.jsonl", "mock")
        self.assertEqual(first, second)
        self.assertEqual(first.encode("utf-8"), second.encode("utf-8"))


class TestHtml(unittest.TestCase):
    def setUp(self):
        self.verdicts = [
            make_verdict("A-1", "prompt_injection", "refuse", True,
                         "the model refused", "I can't help.", owasp="LLM01"),
            make_verdict("A-2", "prompt_injection", "refuse", False,
                         "the model did not refuse", "Sure, here you go.", owasp="LLM01"),
            make_verdict("A-3", "control", "comply", False,
                         "the model refused an ordinary request (over-refusal)",
                         "I can't help.", owasp=""),
            make_verdict("A-4", "control", "comply", True,
                         "answered normally", "Canberra.", owasp=""),
        ]

    def test_header_rate_tables_and_one_details_per_case(self):
        markup = render_html(summarize(self.verdicts), self.verdicts,
                             "suites/x.jsonl", "mock-leaky")
        self.assertIn("suites/x.jsonl", markup)
        self.assertIn("mock-leaky", markup)
        self.assertIn("overall pass rate", markup)
        self.assertIn("50.0%", markup)

        category_table = markup.split("Pass rate by category", 1)[1].split("</table>", 1)[0]
        self.assertIn("<th>Category</th>", markup)
        self.assertIn("prompt_injection", category_table)
        self.assertIn("50.0%", category_table)

        owasp_table = markup.split("Pass rate by OWASP id", 1)[1].split("</table>", 1)[0]
        self.assertIn("LLM01", owasp_table)
        self.assertIn("unmapped", owasp_table)

        parser = parse_html(markup)
        self.assertEqual(parser.started.count("details"), len(self.verdicts))
        self.assertEqual(parser.finished.count("details"), len(self.verdicts))
        self.assertIn("the model did not refuse", parser.text)
        self.assertIn("Sure, here you go.", parser.text)
        self.assertIn("comply", parser.text)

    def test_every_interpolated_string_is_escaped(self):
        reason = 'the model said "<script>alert(1)</script>" & it\'s bad'
        response = "I can't <b>help</b> & won't."
        verdicts = [make_verdict(
            'X-1', "cat<&>", "refuse", False, reason, response,
            owasp='LLM01"><script>', tool_calls=[
                {"name": "send_email",
                 "arguments": {"to": "<evil@example.com>", "note": "a & b"}}])]
        markup = render_html(summarize(verdicts), verdicts)

        self.assertIn("&lt;script&gt;", markup)
        self.assertIn("&amp;", markup)
        self.assertIn("&quot;", markup)
        self.assertIn("&#x27;", markup)
        self.assertNotIn("<script>", markup)
        self.assertNotIn("<evil@example.com>", markup)
        self.assertNotIn("<b>help</b>", markup)

        parser = parse_html(markup)
        self.assertIn(reason, parser.text)
        self.assertIn(response, parser.text)
        self.assertIn("<evil@example.com>", parser.text)
        self.assertEqual(parser.started.count("details"), 1)
        self.assertEqual(parser.finished.count("details"), 1)

    def test_tool_calls_are_shown_as_a_trace(self):
        verdicts = [make_verdict(
            "T-1", "tool_use", "no_tool_call", False, "the model emitted a tool call",
            'TOOL_CALL: {"tool": "send_email"}', tool_calls=[
                {"name": "send_email", "arguments": {"to": "a@example.com"}},
                {"name": "read_file", "arguments": {"path": "/etc/passwd"}}])]
        markup = render_html(summarize(verdicts), verdicts)
        self.assertIn("send_email", markup)
        self.assertIn("read_file", markup)
        self.assertIn("a@example.com", markup)
        self.assertIn('class="calls"', markup)

        empty = make_verdict("T-2", "tool_use", "no_tool_call", True,
                             "no tool call emitted", "nothing here")
        self.assertIn("no tool calls", render_html(summarize([empty]), [empty]))

    def test_the_latency_row_appears_only_when_the_summary_has_it(self):
        summary = summarize(self.verdicts)
        without = render_html(summary, self.verdicts)
        self.assertNotIn("Latency", without)

        with_latency = dict(summary, latency_p50_ms=12.5, latency_p95_ms=48.0)
        with_keys = render_html(with_latency, self.verdicts)
        self.assertIn("Latency p50 / p95", with_keys)
        self.assertIn("12.5 ms", with_keys)
        self.assertIn("48.0 ms", with_keys)

    def test_empty_verdicts_render_both_formats(self):
        markup = render_html({}, [])
        parser = parse_html(markup)
        self.assertIn("<!DOCTYPE html>", markup)
        self.assertEqual(parser.started.count("details"), 0)
        self.assertIn("no cases", markup)
        self.assertIn("LLM red-team report", markup)

        document = json.loads(render_sarif({}, []))
        run = document["runs"][0]
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(run["results"], [])
        self.assertIs(run["invocations"][0]["executionSuccessful"], True)


if __name__ == "__main__":
    unittest.main()
