"""Check the worker's output against the claims format and the fetch log.

Error and drop reasons are fixed codes written by this module. They never
quote worker text, so they are safe to show in the report.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

MAX_STDOUT_BYTES = 2_000_000
MAX_QUESTION = 500
MAX_CLAIMS = 40
MAX_CLAIM_TEXT = 300
MIN_SOURCES, MAX_SOURCES = 1, 5
MAX_EXCERPT = 200
MAX_SUSPICIOUS = 20
MAX_DESCRIPTION = 300
MAX_GAPS = 10
MAX_GAP = 300
MAX_URL = 2048
CONFIDENCE = {"high", "medium", "low"}
TOP_KEYS = {"question", "claims", "suspicious_content", "gaps"}
CLAIM_KEYS = {"id", "text", "sources", "confidence"}
SOURCE_KEYS = {"url", "excerpt"}
SUSPICIOUS_KEYS = {"url", "description"}
CLAIM_ID = re.compile(r"^c[1-9][0-9]{0,2}$")
URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


class WorkerOutputError(Exception):
    """The output as a whole is unusable. The message is a fixed code."""


def extract_result(stdout_text: str) -> str:
    """Return the worker's final message from `claude -p --output-format json` output."""
    if len(stdout_text.encode("utf-8", "replace")) > MAX_STDOUT_BYTES:
        raise WorkerOutputError("worker output too large")
    try:
        envelope = json.loads(stdout_text)
    except ValueError:
        raise WorkerOutputError("worker output is not JSON") from None
    if not isinstance(envelope, dict):
        raise WorkerOutputError("worker output has the wrong shape")
    if envelope.get("is_error") is True:
        raise WorkerOutputError("worker run ended with an error")
    result = envelope.get("result")
    if not isinstance(result, str) or not result.strip():
        raise WorkerOutputError("worker returned no final message")
    return result


def parse_claims(result: str) -> dict:
    """Parse the final message as one JSON object. A single surrounding code fence is tolerated."""
    s = result.strip()
    if s.startswith("```"):
        first_newline = s.find("\n")
        if first_newline == -1 or not s.endswith("```"):
            raise WorkerOutputError("final message is not a JSON object")
        s = s[first_newline + 1 : -3].strip()
    try:
        doc = json.loads(s)
    except ValueError:
        raise WorkerOutputError("final message is not a JSON object") from None
    if not isinstance(doc, dict):
        raise WorkerOutputError("final message is not a JSON object")
    return doc


def normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def check_url(url) -> str | None:
    """Return a drop reason for a URL the report would show, or None if acceptable."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL:
        return "invalid url"
    if not URL_CHARS.match(url):
        return "invalid url"
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # raises on a malformed port
    except ValueError:
        return "invalid url"
    if parts.scheme != "https" or not host:
        return "invalid url"
    return None


def _is_str(value, max_len: int) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) and len(value) <= max_len


def check_document(doc: dict, fetched: set[str]) -> dict:
    """Validate the claims document.

    Raises WorkerOutputError if the document as a whole is malformed.
    Returns {"claims": [...], "suspicious": [...], "gaps": [...], "dropped": {reason: count}}
    with invalid individual items dropped.
    """
    if set(doc) != TOP_KEYS:
        raise WorkerOutputError("final message has missing or extra top-level keys")
    if not _is_str(doc["question"], MAX_QUESTION):
        raise WorkerOutputError("question field is invalid")
    for key, limit in (("claims", MAX_CLAIMS), ("suspicious_content", MAX_SUSPICIOUS), ("gaps", MAX_GAPS)):
        if not isinstance(doc[key], list):
            raise WorkerOutputError(key + " is not a list")
        if len(doc[key]) > limit:
            raise WorkerOutputError(key + " has too many entries")

    dropped: dict[str, int] = {}

    def drop(reason: str) -> None:
        dropped[reason] = dropped.get(reason, 0) + 1

    claims = []
    seen_ids = set()
    for claim in doc["claims"]:
        if not isinstance(claim, dict) or set(claim) != CLAIM_KEYS:
            drop("claim has missing or extra keys")
            continue
        if not isinstance(claim["id"], str) or not CLAIM_ID.match(claim["id"]) or claim["id"] in seen_ids:
            drop("claim id invalid or repeated")
            continue
        if not _is_str(claim["text"], MAX_CLAIM_TEXT):
            drop("claim text missing or too long")
            continue
        if claim["confidence"] not in CONFIDENCE:
            drop("claim confidence invalid")
            continue
        sources = claim["sources"]
        if not isinstance(sources, list) or not (MIN_SOURCES <= len(sources) <= MAX_SOURCES):
            drop("claim has too few or too many sources")
            continue
        ok = True
        for src in sources:
            if not isinstance(src, dict) or set(src) != SOURCE_KEYS:
                ok, reason = False, "source has missing or extra keys"
            elif check_url(src["url"]):
                ok, reason = False, "source url invalid"
            elif normalize_url(src["url"]) not in fetched:
                ok, reason = False, "source was never fetched"
            elif not _is_str(src["excerpt"], MAX_EXCERPT):
                ok, reason = False, "source excerpt missing or too long"
            if not ok:
                break
        if not ok:
            drop(reason)
            continue
        seen_ids.add(claim["id"])
        claims.append(claim)

    suspicious = []
    for item in doc["suspicious_content"]:
        if not isinstance(item, dict) or set(item) != SUSPICIOUS_KEYS:
            drop("suspicious entry has missing or extra keys")
        elif check_url(item["url"]):
            drop("suspicious entry url invalid")
        elif normalize_url(item["url"]) not in fetched:
            drop("suspicious entry url was never fetched")
        elif not _is_str(item["description"], MAX_DESCRIPTION):
            drop("suspicious entry description invalid")
        else:
            suspicious.append(item)

    gaps = []
    for gap in doc["gaps"]:
        if _is_str(gap, MAX_GAP):
            gaps.append(gap)
        else:
            drop("gap entry invalid")

    return {"claims": claims, "suspicious": suspicious, "gaps": gaps, "dropped": dropped}


def read_fetch_log(text: str) -> list[dict]:
    """Parse the guard's JSON-lines log, skipping malformed lines."""
    records = []
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


def fetched_urls(records: list[dict]) -> set[str]:
    out = set()
    for rec in records:
        if rec.get("tool") == "WebFetch" and rec.get("decision") == "allow" and isinstance(rec.get("url"), str):
            if not check_url(rec["url"]):
                out.add(normalize_url(rec["url"]))
    return out
