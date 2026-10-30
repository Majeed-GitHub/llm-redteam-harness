"""Hygiene: the version a user sees must be the version that shipped."""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import rt  # noqa: E402


class TestVersionIsHonest(unittest.TestCase):
    def test_pyproject_matches_the_package(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            text = handle.read()
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        self.assertIsNotNone(match, "pyproject.toml has no version")
        self.assertEqual(match.group(1), rt.__version__)

    def test_the_changelog_documents_the_version(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("## " + rt.__version__, text)

    def test_version_is_semver(self):
        self.assertRegex(rt.__version__, r"^\d+\.\d+\.\d+$")


class TestReleaseHygiene(unittest.TestCase):
    def test_the_console_script_target_exists(self):
        from rt.cli import main
        self.assertTrue(callable(main))

    def test_every_suite_in_the_repository_validates(self):
        from rt.cases import load_cases, validate_cases

        suites = os.path.join(ROOT, "suites")
        paths = sorted(os.path.join(suites, name) for name in os.listdir(suites)
                       if name.endswith((".jsonl", ".json")))
        self.assertTrue(paths)
        for path in paths:
            cases = load_cases(path)
            self.assertEqual(validate_cases(cases), [], os.path.basename(path))


if __name__ == "__main__":
    unittest.main()
