"""Shared helpers for tier 1 tests. No network, no model, no containers."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

FETCH_GUARD = ROOT / "quarantine" / "hooks" / "fetch_guard.py"
GATE = ROOT / "hooks" / "gate.py"
CANARY = "QR-0123456789abcdef0123456789abcdef"


def run_hook(script: Path, payload, env_extra: dict) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": env_extra.get("HOME", "/nonexistent")}
    env.update(env_extra)
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run([sys.executable, str(script)], input=data, capture_output=True,
                          text=True, env=env, timeout=30)


def worker_envelope(final_message: str, is_error: bool = False) -> str:
    """Mimics `claude -p --output-format json` output."""
    return json.dumps({"type": "result", "subtype": "success", "is_error": is_error,
                       "result": final_message, "num_turns": 3})


def good_document(url="https://example.org/a", url2="https://example.net/b") -> dict:
    return {
        "question": "What is the capital of France?",
        "claims": [
            {"id": "c1", "text": "Paris is the capital of France.",
             "sources": [{"url": url, "excerpt": "Paris is the capital"},
                         {"url": url2, "excerpt": "capital: Paris"}],
             "confidence": "high"},
            {"id": "c2", "text": "Paris has about two million residents.",
             "sources": [{"url": url, "excerpt": "about 2.1 million"}],
             "confidence": "medium"},
        ],
        "suspicious_content": [],
        "gaps": [],
    }


def fetch_log(*urls, extra=()) -> str:
    lines = [{"tool": "WebSearch", "query": "capital of france", "decision": "allow", "ts": "t"}]
    lines += [{"tool": "WebFetch", "url": u, "decision": "allow", "ts": "t"} for u in urls]
    lines += list(extra)
    return "\n".join(json.dumps(x) for x in lines) + "\n"
