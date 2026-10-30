# Changelog

## 0.4.0

JUnit XML output, so a CI system can show per-case results instead of one number.

- `rt run --format junit` writes a JUnit XML document to the file named by
  `--report`: one `<testsuite>` named after the suite, one `<testcase>` per case
  (`classname` is the category, `name` is the case id), and a `<failure>` with the
  judge reason for every verdict where `passed` is False. GitHub Actions, GitLab
  and Jenkins render it natively, so a case the model got wrong is a red row you
  can click rather than a line in a log.
- Values are escaped with `xml.sax.saxutils.quoteattr` and `escape`. Judge reasons
  contain quotes and angle brackets; escaping them keeps the document parseable.
- `--format markdown` stays the default and keeps the Markdown report and the JSON
  summary untouched, as does `--json`. `--json-out` still always writes JSON. With
  `--format junit` and no `--report`, the XML goes to stdout.
- `render_junit(summary, verdicts, suite="", model="")` is exported from `rt`
  alongside `render_markdown`, so an embedder can produce the same document
  without going through the CLI.
- Tests in `tests/test_junit.py`: the counts match a summary with a known failure,
  a fully passing run reports `failures="0"`, a reason with quotes and `<`
  round-trips through `xml.etree.ElementTree`, and the CLI writes a file that
  parses.

## Earlier

0.1.0 through 0.3.0 predate this file: suite loading and rule judging, the
deterministic mock model, endpoint comparison, and the host plugin contract.
