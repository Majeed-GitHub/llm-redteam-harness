"""A harness for reproducible LLM security testing.

Point it at any OpenAI-compatible endpoint, or at the mock it ships with, and it
runs a graded suite of attacks, judges the model's behaviour with rules, and
writes a report you can hand to someone else:

    python -m rt run --suite suites/owasp_llm01.jsonl --mock --report report.md
    python -m rt run --suite suites/owasp_llm01.jsonl --endpoint https://api.example.com \
        --model some-model --api-key-env OPENAI_API_KEY

The point is reproducibility, not cleverness. Same suite, same model, same
temperature, same judge: the number means the same thing next month.
"""

from .cases import Case, load_cases, validate_cases
from .client import ChatClient, ClientError
from .judges import Verdict, judge, summarize
from .report import render_junit, render_markdown, write_json

__version__ = "0.6.0"

__all__ = [
    "Case",
    "ChatClient",
    "ClientError",
    "Verdict",
    "judge",
    "load_cases",
    "render_junit",
    "render_markdown",
    "summarize",
    "validate_cases",
    "write_json",
    "__version__",
]
