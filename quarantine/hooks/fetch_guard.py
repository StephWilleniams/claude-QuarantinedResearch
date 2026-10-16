#!/usr/bin/env python3
"""PreToolUse hook for the quarantined research worker.

Runs outside the model, as code, before every tool call the worker makes.
- Logs every WebSearch / WebFetch call (allowed or denied) as JSON lines.
- Denies any tool other than WebSearch and WebFetch.
- Denies calls that contain the canary token.
- Denies suspicious fetch URLs (non-https, IP or local hosts, long query
  strings, long encoded runs, embedded credentials).
- Enforces fetch and search caps.

Fails closed: any error denies the call (exit code 2).

Environment:
  QR_LOG           path of the JSON-lines log (default /home/worker/qr/fetch.log)
  QR_CANARY        canary token planted in the worker prompt
  QR_MAX_FETCHES   max WebFetch calls allowed (default 40)
  QR_MAX_SEARCHES  max WebSearch calls allowed (default 20)
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

ALLOWED_TOOLS = {"WebSearch", "WebFetch"}
MAX_URL_LEN = 2048
MAX_QUERY_STRING_LEN = 200
MAX_SEARCH_QUERY_LEN = 300
BASE64_RUN = re.compile(r"[A-Za-z0-9+/_=-]{64,}")
HEX_RUN = re.compile(r"[0-9a-fA-F]{48,}")
LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".arpa")
NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
NON_ALNUM = re.compile(r"[^a-z0-9]")


def _log_path() -> str:
    return os.environ.get("QR_LOG", "/home/worker/qr/fetch.log")


def _count(tool: str) -> int:
    """Number of ALLOWED calls of this tool so far."""
    n = 0
    try:
        with open(_log_path(), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("tool") == tool and rec.get("decision") == "allow":
                    n += 1
    except FileNotFoundError:
        return 0
    return n


def _log(record: dict) -> None:
    record["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(_log_path(), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def check_url(url: str) -> str | None:
    """Return a reason string if the URL should be blocked, else None."""
    if not isinstance(url, str) or not url:
        return "missing url"
    if len(url) > MAX_URL_LEN:
        return "url too long"
    if any(c.isspace() for c in url) or any(ord(c) < 32 or ord(c) > 126 for c in url):
        return "url has whitespace or non-ascii characters"
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "only https urls are allowed"
    if parts.username or parts.password or "@" in parts.netloc:
        return "credentials in url"
    if "%" in parts.netloc or "\\" in parts.netloc:
        return "encoded characters in host"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "missing host"
    try:
        ipaddress.ip_address(host)
        return "ip address hosts are not allowed"
    except ValueError:
        pass
    labels = host.split(".")
    if all(NUMERIC_LABEL.match(l) for l in labels) or NUMERIC_LABEL.match(labels[-1]):
        return "ip address hosts are not allowed"   # 127.1, 0x7f.1, 2130706433 and similar
    if host == "localhost" or "." not in host or host.endswith(LOCAL_SUFFIXES):
        return "local host names are not allowed"
    if parts.port not in (None, 443):
        return "non-standard port"
    if len(parts.query) > MAX_QUERY_STRING_LEN:
        return "query string too long"
    tail = parts.path + "?" + parts.query + "#" + parts.fragment
    if BASE64_RUN.search(tail) or HEX_RUN.search(tail):
        return "long encoded run in url"
    return None


def decide(payload: dict, canary: str) -> tuple[str, str, dict]:
    """Return (decision, reason, log_fields)."""
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    fields = {"tool": tool}
    if tool not in ALLOWED_TOOLS:
        return "deny", "tool not allowed in quarantine", fields

    serialized = json.dumps(tool_input, ensure_ascii=False)
    canary_core = NON_ALNUM.sub("", canary.lower())[2:] if canary else ""   # drop the "qr" prefix
    if canary and (canary in serialized or
                   (len(canary_core) >= 16 and canary_core in NON_ALNUM.sub("", serialized.lower()))):
        fields["canary"] = True
        return "deny", "canary token found in tool input", fields

    if tool == "WebFetch":
        url = tool_input.get("url", "")
        fields["url"] = url if isinstance(url, str) else repr(url)
        reason = check_url(url)
        if reason:
            return "deny", reason, fields
        cap = int(os.environ.get("QR_MAX_FETCHES", "40"))
        if _count("WebFetch") >= cap:
            return "deny", "fetch cap reached", fields
        return "allow", "", fields

    # WebSearch
    query = tool_input.get("query", "")
    fields["query"] = query if isinstance(query, str) else repr(query)
    if not isinstance(query, str) or not query.strip():
        return "deny", "missing query", fields
    if len(query) > MAX_SEARCH_QUERY_LEN:
        return "deny", "search query too long", fields
    if BASE64_RUN.search(query) or HEX_RUN.search(query):
        return "deny", "long encoded run in query", fields
    cap = int(os.environ.get("QR_MAX_SEARCHES", "20"))
    if _count("WebSearch") >= cap:
        return "deny", "search cap reached", fields
    return "allow", "", fields


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read())
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        # One decision at a time, so parallel tool calls cannot overrun the caps.
        with open(_log_path() + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            decision, reason, fields = decide(payload, os.environ.get("QR_CANARY", ""))
            fields["decision"] = decision
            if reason:
                fields["reason"] = reason
            _log(fields)
        if decision == "deny":
            sys.stderr.write("Blocked by quarantine guard: " + reason + "\n")
            return 2
        return 0
    except Exception as exc:  # fail closed
        try:
            _log({"tool": "?", "decision": "deny", "reason": "guard error: " + type(exc).__name__})
        except Exception:
            pass
        sys.stderr.write("Blocked by quarantine guard: internal error\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
