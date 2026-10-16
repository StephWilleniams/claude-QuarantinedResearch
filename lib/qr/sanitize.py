"""Strip anything from worker text that could hide instructions or render as active content.

Applied to every text field the worker returns. URLs are handled separately
(validate.check_url) and are never sanitized into something else: a bad URL is
rejected, not repaired.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter

HTML_COMMENT = re.compile(r"<!--.*?(?:-->|$)", re.S)
HTML_TAG = re.compile(r"</?[A-Za-z!?][^<>]{0,500}>")
MD_IMAGE = re.compile(r"!\[[^\]\n]{0,500}\]\([^)\n]{0,2048}\)")
MD_LINK = re.compile(r"\[([^\]\n]{0,500})\]\(([^)\n]{0,2048})\)")
MD_REF_DEF = re.compile(r"^\s{0,3}\[[^\]\n]{1,200}\]:\s*\S+.*$", re.M)
WHITESPACE = re.compile(r"\s+")
MAX_COMBINING = 2  # combining marks allowed on one base character

# Characters that render as nothing (or as blank space) but are not category Cf.
INVISIBLE = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0)) | {
    0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F,
    0x2800, 0x3164, 0xFFA0, 0x1D159, 0x1D173, 0x1D174, 0x1D175, 0x1D176,
    0x1D177, 0x1D178, 0x1D179, 0x1D17A,
}

# Unicode categories removed outright: format (zero-width, bidi controls, tag
# characters), private use, surrogates, unassigned.
REMOVED_CATEGORIES = {"Cf": "invisible", "Co": "private_use", "Cs": "surrogate", "Cn": "unassigned"}


def sanitize_text(text: str, counts: Counter | None = None) -> str:
    """Return a cleaned single-line string. Removal counts are added to `counts`."""
    if counts is None:
        counts = Counter()
    s = unicodedata.normalize("NFKC", text)

    out = []
    combining_run = 0
    for ch in s:
        cat = unicodedata.category(ch)
        if ord(ch) in INVISIBLE:
            counts["invisible"] += 1
            continue
        if cat in ("Mn", "Me"):
            combining_run += 1
            if combining_run > MAX_COMBINING:
                counts["combining_marks"] += 1
                continue
        else:
            combining_run = 0
        if cat in REMOVED_CATEGORIES:
            counts[REMOVED_CATEGORIES[cat]] += 1
            continue
        if cat == "Cc":
            if ch in "\t\n\r":
                out.append(" ")
            else:
                counts["control"] += 1
            continue
        out.append(ch)
    s = "".join(out)

    s, n = HTML_COMMENT.subn("", s)
    counts["html_comment"] += n
    s, n = HTML_TAG.subn("", s)
    counts["html_tag"] += n
    s, n = MD_IMAGE.subn("", s)
    counts["markdown_image"] += n
    s, n = MD_REF_DEF.subn("", s)
    counts["markdown_link"] += n
    s, n = MD_LINK.subn(lambda m: m.group(1) + " (" + m.group(2) + ")", s)
    counts["markdown_link"] += n

    s = WHITESPACE.sub(" ", s).strip()
    return s


def summarize(counts: Counter) -> dict:
    """Only non-zero counts, in a stable order."""
    return {k: counts[k] for k in sorted(counts) if counts[k]}
