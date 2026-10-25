"""Tests for the embedding contract a host plugin uses."""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rt.plugin import SCHEMA, plugin_manifest, plugin_run  # noqa: E402

SUITE = os.path.join(ROOT, "suites", "owasp_llm01.jsonl")


class TestManifest(unittest.TestCase):
    def test_the_manifest_declares_what_a_host_needs(self):
        manifest = plugin_manifest()
        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertTrue(manifest["entrypoint"]["args"])
        self.assertEqual(len(manifest["commands"]), 2)
        for key in ("network", "filesystem", "secrets", "subprocesses"):
            self.assertIn(key, manifest["permissions"])

    def test_the_manifest_is_json_serialisable(self):
        json.dumps(plugin_manifest())

    def test_the_manifest_states_that_it_measures_rather_than_bypasses(self):
        text = json.dumps(plugin_manifest()).lower()
        self.assertIn("measures", text)
        self.assertIn("does not bypass", text)


class TestPluginRun(unittest.TestCase):
    def test_a_good_endpoint_scores_zero(self):
        result = plugin_run(SUITE, mock=True, mock_mode="good")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["summary"]["attack_success_rate"], 0.0)
        self.assertIn("LLM security test report", result["markdown"])
        self.assertIn("by_category", result)

    def test_a_leaky_endpoint_scores_one(self):
        result = plugin_run(SUITE, mock=True, mock_mode="leaky")
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["attack_success_rate"], 1.0)
        self.assertGreater(len(result["failures"]), 0)

    def test_an_invalid_suite_is_an_error_not_a_crash(self):
        result = plugin_run(os.path.join(ROOT, "README.md"), mock=True)
        self.assertFalse(result["ok"])
        self.assertIn("not valid", result["error"])

    def test_no_endpoint_is_an_error(self):
        result = plugin_run(SUITE)
        self.assertFalse(result["ok"])
        self.assertIn("no endpoint", result["error"])

    def test_the_report_path_is_written(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.md")
            result = plugin_run(SUITE, mock=True, report_path=path)
            self.assertEqual(result["report_path"], path)
            with open(path, "r", encoding="utf-8") as handle:
                self.assertIn("LLM security test report", handle.read())


class TestPluginCli(unittest.TestCase):
    def run_cli(self, args):
        return subprocess.run([sys.executable, "-m", "rt"] + args, cwd=ROOT,
                              capture_output=True, text=True, timeout=600)

    def test_manifest_cli(self):
        result = self.run_cli(["plugin-manifest"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["schema"], SCHEMA)

    def test_run_cli_emits_json(self):
        result = self.run_cli(["plugin-run", "--suite", "suites/owasp_llm01.jsonl",
                               "--mock", "--mock-mode", "good"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["attack_success_rate"], 0.0)

    def test_max_asr_fails_a_leaky_run(self):
        result = self.run_cli(["plugin-run", "--suite", "suites/owasp_llm01.jsonl",
                               "--mock", "--mock-mode", "leaky", "--max-asr", "0.1"])
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
