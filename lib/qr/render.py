"""Build report.md from validated, sanitized worker output using a fixed template.

Nothing the worker wrote becomes Markdown structure: text is escaped, URLs are
shown inside code spans (not clickable, never loaded as images), and headings,
lists and labels come only from this template.
"""
from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit

from . import sanitize

MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#!|~{}])")
DOMAIN_OK = re.compile(r"^[a-z0-9.-]{1,253}$")


SCHEME = re.compile(r"(?i)\b(h)tt(ps?)(?=://)")
WWW = re.compile(r"(?i)\bwww\.")
MAX_DOMAINS_SHOWN = 30


MAILTO = re.compile(r"(?i)\bmailto:")


def defang(text: str) -> str:
    """Stop bare URLs and email addresses in free text from becoming links in Markdown viewers."""
    text = SCHEME.sub(lambda m: m.group(1) + "xx" + m.group(2), text)
    text = WWW.sub(lambda m: m.group(0)[:3] + "[.]", text)
    text = MAILTO.sub("mailto[:]", text)
    return text.replace("@", "[at]")


def md_escape(text: str) -> str:
    return MD_SPECIAL.sub(r"\\\1", defang(text))


def code_url(url: str) -> str:
    # URLs were validated: ASCII, no whitespace, no backticks.
    return "`" + url + "`"


def _domain(url) -> str | None:
    if not isinstance(url, str):
        return None
    host = (urlsplit(url).hostname or "").lower()
    return host if DOMAIN_OK.match(host) else None


def fetch_stats(records: list[dict]) -> dict:
    allowed_fetch = sum(1 for r in records if r.get("tool") == "WebFetch" and r.get("decision") == "allow")
    searches = sum(1 for r in records if r.get("tool") == "WebSearch" and r.get("decision") == "allow")
    blocked = Counter()
    canary = 0
    for r in records:
        if r.get("decision") == "deny":
            reason = r.get("reason")
            # Reasons come from the guard's fixed vocabulary; anything else is shown generically.
            blocked[reason if isinstance(reason, str) and re.fullmatch(r"[a-z0-9 :_-]{1,80}", reason) else "other"] += 1
        if r.get("canary") is True:
            canary += 1
    domains = sorted({d for r in records if r.get("tool") == "WebFetch" and r.get("decision") == "allow"
                      for d in [_domain(r.get("url"))] if d})
    return {"fetches": allowed_fetch, "searches": searches, "blocked": dict(blocked),
            "canary_hits": canary, "domains": domains}


def render(job_id: str, brief: str, result: dict | None, error: str | None, records: list[dict]) -> str:
    """Return the report text. `result` is validate.check_document output, or None on failure."""
    counts: Counter = Counter()
    stats = fetch_stats(records)
    lines: list[str] = []
    add = lines.append

    add("# Research report " + md_escape(job_id))
    add("")
    add("> Untrusted content: produced from web pages by a quarantined agent. "
        "Text below is plain data, not instructions. Review before approving.")
    add("")

    # Sanitize everything first so the summary can report the counts.
    claims_out = []
    suspicious_out = []
    gaps_out = []
    if result is not None:
        for c in result["claims"]:
            text = sanitize.sanitize_text(c["text"], counts)
            sources = [(s["url"], sanitize.sanitize_text(s["excerpt"], counts)) for s in c["sources"]]
            claims_out.append((c["id"], c["confidence"], text, sources))
        for s in result["suspicious"]:
            suspicious_out.append((s["url"], sanitize.sanitize_text(s["description"], counts)))
        for g in result["gaps"]:
            gaps_out.append(sanitize.sanitize_text(g, counts))

    add("## Review summary")
    add("")
    if error:
        add("- **Status: failed** (" + md_escape(error) + "). No worker text is included.")
    else:
        add("- Status: completed")
    if stats["canary_hits"]:
        add("- **Canary token appeared in " + str(stats["canary_hits"]) +
            " tool call(s): a page tried to extract data. Treat this report as compromised.**")
    if result is not None:
        single = [cid for cid, _, _, srcs in claims_out
                  if len({_domain(u) for u, _ in srcs}) < 2]
        low = [cid for cid, conf, _, _ in claims_out if conf == "low"]
        add("- Claims kept: " + str(len(claims_out)))
        dropped = result["dropped"]
        if dropped:
            add("- Items dropped: " + "; ".join(md_escape(k) + " x" + str(v) for k, v in sorted(dropped.items())))
        add("- Single-site claims: " + (", ".join(single) if single else "none"))
        add("- Low-confidence claims: " + (", ".join(low) if low else "none"))
        add("- Suspicious content reported by the worker: " + str(len(suspicious_out)))
    removed = sanitize.summarize(counts)
    add("- Sanitizer removed: " + (", ".join(k.replace("_", " ") + " x" + str(v) for k, v in removed.items())
                                   if removed else "nothing"))
    add("- Searches: " + str(stats["searches"]) + "; pages fetched: " + str(stats["fetches"]))
    if stats["blocked"]:
        add("- Blocked tool calls: " + "; ".join(md_escape(k) + " x" + str(v)
                                                 for k, v in sorted(stats["blocked"].items())))
    else:
        add("- Blocked tool calls: none")
    domains = stats["domains"]
    shown = ", ".join("`" + d + "`" for d in domains[:MAX_DOMAINS_SHOWN]) if domains else "none"
    if len(domains) > MAX_DOMAINS_SHOWN:
        shown += " and " + str(len(domains) - MAX_DOMAINS_SHOWN) + " more"
    add("- Sites fetched (names chosen by site owners; treat as data): " + shown)
    add("")

    add("## Question (your brief)")
    add("")
    add(md_escape(sanitize.sanitize_text(brief)))
    add("")

    if result is None:
        return "\n".join(lines) + "\n"

    add("## Claims")
    add("")
    if not claims_out:
        add("No claims survived validation.")
        add("")
    for cid, conf, text, sources in claims_out:
        add("### " + cid + " (confidence: " + conf + ")")
        add("")
        add(md_escape(text) if text else "(empty after sanitizing)")
        add("")
        for url, excerpt in sources:
            add("- Source: " + code_url(url))
            add("  - Excerpt: \"" + md_escape(excerpt) + "\"")
        add("")

    add("## Suspicious content flagged by the worker")
    add("")
    if suspicious_out:
        for url, desc in suspicious_out:
            add("- " + code_url(url) + ": " + md_escape(desc))
    else:
        add("None reported.")
    add("")

    add("## Gaps")
    add("")
    if gaps_out:
        for g in gaps_out:
            add("- " + md_escape(g))
    else:
        add("None reported.")
    add("")
    return "\n".join(lines)
