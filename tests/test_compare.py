"""Gateway mode: the same suite against several endpoints, tabulated."""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rt.cases import load_cases  # noqa: E402
from rt.client import ChatClient  # noqa: E402
from rt.mock import serve  # noqa: E402
from rt.runner import compare, render_comparison, run_suite  # noqa: E402

SUITE = os.path.join(ROOT, "suites", "owasp_llm01.jsonl")
CASES = load_cases(SUITE)[:8]


class TestRunner(unittest.TestCase):
    def test_one_run_records_verdicts_and_latency(self):
        server, endpoint = serve(mode="good")
        try:
            run = run_suite(CASES, ChatClient(endpoint=endpoint, model="mock", timeout=30), name="good")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(run.verdicts), len(CASES))
        self.assertEqual(len(run.latencies_ms), len(CASES))
        self.assertGreater(run.latency(0.5), 0.0)
        self.assertEqual(run.summary["attack_success_rate"], 0.0)

    def test_an_unreachable_endpoint_is_recorded_not_raised(self):
        run = run_suite(CASES, ChatClient(endpoint="http://127.0.0.1:1", model="none", timeout=2), name="dead")
        self.assertTrue(run.error)
        self.assertEqual(run.verdicts, [])
        self.assertIn("could not be reached", render_comparison([run]))


class TestComparison(unittest.TestCase):
    def test_two_endpoints_are_ranked_honestly(self):
        good, good_url = serve(mode="good")
        leaky, leaky_url = serve(mode="leaky")
        try:
            runs = compare([("good", good_url), ("leaky", leaky_url)], CASES, model="mock", timeout=30)
        finally:
            good.shutdown()
            good.server_close()
            leaky.shutdown()
            leaky.server_close()
        rates = {run.name: run.summary["attack_success_rate"] for run in runs}
        self.assertEqual(rates["good"], 0.0)
        self.assertGreater(rates["leaky"], 0.5)

        table = render_comparison(runs, "suites/owasp_llm01.jsonl")
        self.assertIn("| good |", table)
        self.assertIn("| leaky |", table)
        self.assertIn("Lower attack success rate is better", table)

    def test_the_comparison_reports_over_refusal(self):
        good, good_url = serve(mode="good")
        try:
            runs = compare([("good", good_url)], CASES, model="mock", timeout=30)
        finally:
            good.shutdown()
            good.server_close()
        self.assertIn("over_refusal_rate", runs[0].summary)


class TestCompareCli(unittest.TestCase):
    def test_the_cli_tabulates_two_mocks(self):
        good, good_url = serve(mode="good")
        leaky, leaky_url = serve(mode="leaky")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "rt", "compare", "--suite", "suites/owasp_llm01.jsonl",
                 "--target", "good=" + good_url, "--target", "leaky=" + leaky_url,
                 "--model", "mock", "--json"],
                cwd=ROOT, capture_output=True, text=True, timeout=600)
        finally:
            good.shutdown()
            good.server_close()
            leaky.shutdown()
            leaky.server_close()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 2)
        self.assertLess(rows[0]["summary"]["attack_success_rate"],
                        rows[1]["summary"]["attack_success_rate"])

    def test_a_malformed_target_is_rejected(self):
        result = subprocess.run(
            [sys.executable, "-m", "rt", "compare", "--suite", "suites/owasp_llm01.jsonl",
             "--target", "no-equals-sign"],
            cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
