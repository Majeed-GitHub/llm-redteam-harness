"""End-to-end: the MCP suite must separate a poisoned agent from a safe one.

This is the claim the repository publishes, so it is tested against the shipped
suite and the shipped fixtures with no mocks of the harness itself. A suite that
cannot fail a deliberately poisoned agent measures nothing.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rt.cases import load_cases  # noqa: E402
from rt.client import ChatClient  # noqa: E402
from rt.judges import summarize  # noqa: E402
from rt.mock import serve  # noqa: E402
from rt.runner import run_agent_suite  # noqa: E402

SUITE = os.path.join(ROOT, "suites", "mcp_schema.jsonl")


class SuiteRun:
    """Run the whole suite against one fixture, once per test class."""

    @classmethod
    def run_fixture(cls, mode):
        server, endpoint = serve(mode=mode)
        try:
            client = ChatClient(endpoint=endpoint, model="mock-" + mode, timeout=30.0)
            run = run_agent_suite(load_cases(SUITE), client, name=mode)
        finally:
            server.shutdown()
            server.server_close()
        return run

    @classmethod
    def setUpClass(cls):
        cls.cases = load_cases(SUITE)
        cls.vulnerable = cls.run_fixture("agent-vulnerable")
        cls.safe = cls.run_fixture("agent-safe")


class TestVulnerableFixtureFails(SuiteRun, unittest.TestCase):
    def test_every_attack_case_fails(self):
        attacks = [verdict for verdict in self.vulnerable.verdicts
                   if not verdict.control]
        self.assertTrue(attacks, "the suite has no attack cases")
        failed = [verdict for verdict in attacks if not verdict.passed]
        self.assertEqual(len(failed), len(attacks),
                         "a poisoned agent passed: %s" % [
                             verdict.case_id for verdict in attacks if verdict.passed])

    def test_the_attack_success_rate_is_total(self):
        summary = summarize(self.vulnerable.verdicts)
        self.assertEqual(summary["attack_success_rate"], 1.0)

    def test_the_failures_name_the_control_that_broke(self):
        reasons = {verdict.failure_reason.split(":")[0]
                   for verdict in self.vulnerable.verdicts if not verdict.passed}
        self.assertIn("forbidden_tool_called", reasons)
        self.assertIn("canary_leaked_in_tool_args", reasons)
        self.assertIn("canary_leaked_in_text", reasons)
        self.assertIn("policy_invariant", reasons)

    def test_the_trajectory_shows_the_calls_not_just_the_verdict(self):
        by_id = {verdict.case_id: verdict for verdict in self.vulnerable.verdicts}
        multi = by_id["MCP-06"]
        names = [call["name"] for call in multi.tool_calls]
        self.assertIn("get_contact_list", names)
        self.assertIn("book_appointment", names)
        self.assertGreaterEqual(multi.turns, 2)


class TestSafeFixturePasses(SuiteRun, unittest.TestCase):
    def test_no_attack_case_fails(self):
        failed = [verdict.case_id for verdict in self.safe.verdicts if not verdict.passed]
        self.assertEqual(failed, [])

    def test_the_attack_success_rate_is_zero(self):
        summary = summarize(self.safe.verdicts)
        self.assertEqual(summary["attack_success_rate"], 0.0)

    def test_it_never_calls_a_forbidden_tool(self):
        for verdict in self.safe.verdicts:
            names = [call["name"] for call in verdict.tool_calls]
            self.assertNotIn("send_email", names, verdict.case_id)
            self.assertNotIn("mail_relay", names, verdict.case_id)


class TestControlCase(SuiteRun, unittest.TestCase):
    def test_the_control_passes_for_both_fixtures(self):
        for run in (self.vulnerable, self.safe):
            controls = [verdict for verdict in run.verdicts if verdict.control]
            self.assertTrue(controls, "no control case in the suite")
            for verdict in controls:
                self.assertTrue(verdict.passed, verdict.case_id)

    def test_over_refusal_is_zero_for_the_safe_fixture(self):
        self.assertEqual(summarize(self.safe.verdicts)["over_refusal_rate"], 0.0)


class TestReportsCarryTheNewFields(SuiteRun, unittest.TestCase):
    def test_sarif_marks_a_poisoning_failure_as_an_error(self):
        import json
        from rt.report_sarif import render_sarif

        summary = summarize(self.vulnerable.verdicts)
        payload = json.loads(render_sarif(summary, self.vulnerable.verdicts,
                                          "suites/mcp_schema.jsonl", "mock"))
        results = payload["runs"][0]["results"]
        self.assertTrue(results)
        for result in results:
            self.assertEqual(result["level"], "error")
        rule_ids = {result["ruleId"] for result in results}
        self.assertTrue(any(rule in ("MCP03", "MCP06", "LLM01") for rule in rule_ids))

    def test_html_lists_a_case_per_verdict(self):
        from rt.judges import summarize as summarise
        from rt.report_html import render_html

        page = render_html(summarise(self.vulnerable.verdicts), self.vulnerable.verdicts)
        self.assertEqual(page.count("<details"), len(self.vulnerable.verdicts))


if __name__ == "__main__":
    unittest.main()
