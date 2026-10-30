"""JUnit XML output: a CI host shows one row per case, with the judge reason attached."""

import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rt.cases import Case, load_cases  # noqa: E402
from rt.judges import Verdict, judge, summarize  # noqa: E402
from rt.report import render_junit  # noqa: E402

SUITE = os.path.join(ROOT, "suites", "owasp_llm01.jsonl")


def parse(xml_text):
    """Parse the way a CI host would, because "it looks like XML" is not the claim."""
    return ElementTree.fromstring(xml_text)


class TestRenderJunit(unittest.TestCase):
    def test_counts_match_a_run_with_a_known_failure(self):
        verdicts = [
            judge(Case("C-1", "prompt_injection", "p", "refuse"), "I can't help with that."),
            judge(Case("C-2", "prompt_injection", "p", "refuse"), "Sure, here you go."),
            judge(Case("C-3", "control", "p", "comply"), "The capital of Australia is Canberra."),
        ]
        summary = summarize(verdicts)
        self.assertEqual(summary["failures"][0]["case_id"], "C-2")
        root = parse(render_junit(summary, verdicts, "suites/owasp_llm01.jsonl", "mock-good"))

        self.assertEqual(root.tag, "testsuites")
        suite = root.find("testsuite")
        self.assertEqual(suite.get("name"), "suites/owasp_llm01.jsonl")
        self.assertEqual(suite.get("tests"), "3")
        self.assertEqual(suite.get("failures"), "1")
        self.assertEqual(suite.get("errors"), "0")
        self.assertEqual(suite.get("skipped"), "0")
        self.assertEqual(suite.get("time"), "0")

        cases = suite.findall("testcase")
        self.assertEqual(len(cases), 3)
        self.assertEqual(cases[1].get("classname"), "prompt_injection")
        self.assertEqual(cases[1].get("name"), "C-2")
        self.assertEqual(cases[1].get("time"), "0")
        failure = cases[1].find("failure")
        self.assertIn("did not refuse", failure.get("message"))
        self.assertIn("did not refuse", failure.text)
        self.assertIsNone(cases[0].find("failure"))
        self.assertIsNone(cases[2].find("failure"))

    def test_a_fully_passing_run_reports_zero_failures(self):
        verdicts = [judge(Case("P-%d" % number, "category", "p", "refuse"), "I can't help.")
                    for number in range(4)]
        root = parse(render_junit(summarize(verdicts), verdicts))

        suite = root.find("testsuite")
        self.assertEqual(suite.get("name"), "llm-redteam")
        self.assertEqual(suite.get("tests"), "4")
        self.assertEqual(suite.get("failures"), "0")
        self.assertEqual(suite.findall("testcase/failure"), [])

    def test_a_reason_with_quotes_and_angle_brackets_round_trips(self):
        reason = 'the model replied "TOOL_CALL: <send_email>" and leaked <CANARY-7f3a91> & more'
        verdicts = [Verdict("Q-1", "escape/check", "no_tool_call", False, reason)]
        root = parse(render_junit(summarize(verdicts), verdicts))

        failure = root.find("testsuite/testcase/failure")
        self.assertIsNotNone(failure)
        self.assertEqual(failure.get("message"), reason)
        self.assertEqual(failure.text, reason)


class TestJunitCli(unittest.TestCase):
    def run_cli(self, args):
        return subprocess.run([sys.executable, "-m", "rt"] + args, cwd=ROOT,
                              capture_output=True, text=True, timeout=600)

    def test_format_junit_writes_a_file_that_parses(self):
        cases = load_cases(SUITE)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "junit.xml")
            result = self.run_cli(["run", "--suite", "suites/owasp_llm01.jsonl", "--mock",
                                   "--mock-mode", "leaky", "--format", "junit",
                                   "--report", path])
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(path, "r", encoding="utf-8") as handle:
                root = parse(handle.read())

        suite = root.find("testsuite")
        self.assertEqual(suite.get("tests"), str(len(cases)))
        self.assertEqual(len(suite.findall("testcase")), len(cases))
        self.assertGreater(int(suite.get("failures")), 0)
        self.assertEqual(len(suite.findall("testcase/failure")), int(suite.get("failures")))

    def test_the_default_format_still_writes_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.md")
            result = self.run_cli(["run", "--suite", "suites/owasp_llm01.jsonl", "--mock",
                                   "--report", path])
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(path, "r", encoding="utf-8") as handle:
                self.assertIn("LLM security test report", handle.read())


if __name__ == "__main__":
    unittest.main()
