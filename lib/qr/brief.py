"""Check a research brief before it leaves your machine.

The brief is the only thing the worker learns about you, so it must be short
and must not carry secrets, file contents or private paths.
"""
from __future__ import annotations

import re

MAX_BRIEF = 2000
MAX_LINES = 20

SECRET_PATTERNS = [
    ("anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("api key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("aws key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("long encoded string", re.compile(r"[A-Za-z0-9+=_]{40,}")),
    ("password", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S+")),
    ("local path", re.compile(r"(?:/Users/|/home/|~/|\b[A-Za-z]:\\)")),
    ("email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]


def check_brief(brief) -> list[str]:
    """Return a list of problems (empty means the brief is acceptable)."""
    if not isinstance(brief, str):
        return ["brief is not text"]
    problems = []
    stripped = brief.strip()
    if not stripped:
        problems.append("brief is empty")
    if len(brief) > MAX_BRIEF:
        problems.append("brief is longer than %d characters" % MAX_BRIEF)
    if brief.count("\n") >= MAX_LINES:
        problems.append("brief has more than %d lines; it looks like pasted content" % MAX_LINES)
    if stripped.startswith("-"):
        problems.append("brief must not start with '-'")
    if any(ord(c) < 32 and c not in "\n\t" for c in brief):
        problems.append("brief contains control characters")
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(brief):
            problems.append("brief looks like it contains a %s" % label)
    return problems
